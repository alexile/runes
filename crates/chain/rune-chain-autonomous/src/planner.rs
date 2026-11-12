//! Pluggable task planning and prioritisation.

use std::collections::VecDeque;
use std::fmt::Write as _;

use async_trait::async_trait;
use rune_chain_core::{ChainError, Llm, Message};

use crate::untrusted::{UNTRUSTED_NOTICE, fence};
use crate::{Task, TaskRecord};

/// What a planner sees: the goal, recent results and the pending queue.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct PlanContext<'a> {
    /// The caller's goal.
    pub goal: &'a str,
    /// Recent completed tasks, oldest first (bounded by
    /// [`Limits::max_history`](crate::Limits::max_history)).
    pub history: &'a VecDeque<TaskRecord>,
    /// Pending tasks, next first.
    pub queue: &'a VecDeque<Task>,
    /// Planning rounds adopted so far.
    pub cycle: usize,
    /// Byte budget for quoting results into a prompt.
    pub max_context_bytes: usize,
}

impl<'a> PlanContext<'a> {
    /// A context for `goal` with the default 16 KiB context budget, mainly
    /// for testing planners.
    #[must_use]
    pub const fn new(
        goal: &'a str,
        history: &'a VecDeque<TaskRecord>,
        queue: &'a VecDeque<Task>,
    ) -> Self {
        Self {
            goal,
            history,
            queue,
            cycle: 0,
            max_context_bytes: 16 * 1024,
        }
    }

    /// Recent results fenced as `<task_result>` blocks, newest kept first
    /// when they do not all fit in
    /// [`max_context_bytes`](Self::max_context_bytes).
    ///
    /// ```rust
    /// use std::collections::VecDeque;
    /// use rune_chain_autonomous::PlanContext;
    ///
    /// let (history, queue) = (VecDeque::new(), VecDeque::new());
    /// let ctx = PlanContext::new("goal", &history, &queue);
    /// assert_eq!(ctx.render_history(), "(no tasks completed yet)");
    /// ```
    #[must_use]
    pub fn render_history(&self) -> String {
        render_history(self.history, self.max_context_bytes)
    }

    /// Pending tasks, each fenced as a `<task>` block.
    #[must_use]
    pub fn render_queue(&self) -> String {
        if self.queue.is_empty() {
            return "(none)".to_owned();
        }
        self.queue
            .iter()
            .map(|t| fence("task", &format!("id=\"{}\"", t.id), &t.description))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

pub fn render_history(history: &VecDeque<TaskRecord>, max_bytes: usize) -> String {
    if history.is_empty() {
        return "(no tasks completed yet)".to_owned();
    }
    let mut blocks = Vec::new();
    let mut used = 0usize;
    for record in history.iter().rev() {
        let block = fence(
            "task_result",
            &format!("id=\"{}\"", record.task.id),
            &format!(
                "Task: {}\nResult: {}",
                record.task.description, record.result
            ),
        );
        if used + block.len() > max_bytes {
            break;
        }
        used += block.len() + 1;
        blocks.push(block);
    }
    let omitted = history.len() - blocks.len();
    blocks.reverse();
    let mut out = String::new();
    if omitted > 0 {
        let _ = writeln!(out, "({omitted} earlier results omitted)");
    }
    out.push_str(&blocks.join("\n"));
    out
}

/// A planner's verdict after the queue ran empty.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Review {
    /// The goal is achieved.
    Done {
        /// The final answer.
        answer: String,
    },
    /// More work is needed.
    Continue {
        /// New tasks, in the order they should run. They are cleaned,
        /// de-duplicated and capped before entering the queue.
        tasks: Vec<String>,
    },
}

/// Decides what the agent works on.
///
/// The agent calls [`plan`](Self::plan) once at the start,
/// [`after_task`](Self::after_task) after every task (BabyAGI-style task
/// creation, off in the default planner) and [`review`](Self::review)
/// whenever the queue runs empty. [`prioritize`](Self::prioritize) may reorder
/// the queue after tasks are added.
///
/// `llm` is the run's governed LLM: calls made through it count against the
/// run's limits and fail once a limit is hit. Whatever a planner returns is
/// treated as untrusted text and bounded by [`Limits`](crate::Limits); a
/// planner cannot extend the run beyond them.
///
/// ```rust
/// use async_trait::async_trait;
/// use rune_chain_autonomous::{PlanContext, Review, TaskPlanner};
/// use rune_chain_core::{ChainError, Llm};
///
/// /// Runs a fixed checklist, then reports the last result.
/// struct Checklist(Vec<String>);
///
/// #[async_trait]
/// impl TaskPlanner for Checklist {
///     async fn plan(&self, _: &dyn Llm, _: &PlanContext<'_>) -> Result<Vec<String>, ChainError> {
///         Ok(self.0.clone())
///     }
///     async fn review(&self, _: &dyn Llm, ctx: &PlanContext<'_>) -> Result<Review, ChainError> {
///         let answer = ctx.history.back().map(|r| r.result.clone()).unwrap_or_default();
///         Ok(Review::Done { answer })
///     }
/// }
/// ```
#[async_trait]
pub trait TaskPlanner: Send + Sync {
    /// The initial task list for the goal.
    async fn plan(&self, llm: &dyn Llm, ctx: &PlanContext<'_>) -> Result<Vec<String>, ChainError>;

    /// Judge progress once the queue is empty.
    async fn review(&self, llm: &dyn Llm, ctx: &PlanContext<'_>) -> Result<Review, ChainError>;

    /// New tasks to queue after `record` finished. Default: none.
    async fn after_task(
        &self,
        _llm: &dyn Llm,
        _ctx: &PlanContext<'_>,
        _record: &TaskRecord,
    ) -> Result<Vec<String>, ChainError> {
        Ok(Vec::new())
    }

    /// Reorder the pending queue. Default: keep it first-in, first-out.
    fn prioritize(&self, _ctx: &PlanContext<'_>, _queue: &mut VecDeque<Task>) {}
}

/// The default planner: asks the LLM for a numbered task list, then reviews
/// progress with a strict `STATUS: DONE` / `STATUS: CONTINUE` format.
///
/// Completed results are quoted in fenced `<task_result>` blocks in the user
/// turn; the system prompts are fixed. A review reply without a `STATUS:`
/// line or numbered list is a [`ChainError::ParseError`] rather than being
/// guessed at.
#[derive(Debug, Clone, Default)]
pub struct LlmPlanner {
    create_tasks_after_each: bool,
}

const PLAN_SYSTEM: &str = "You are the planning component of an autonomous agent. \
You break a goal into a short ordered list of concrete tasks.";
const REVIEW_SYSTEM: &str = "You are the evaluator of an autonomous agent. \
You judge whether the goal has been achieved from the results so far.";

impl LlmPlanner {
    /// The default planner.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Also ask the LLM for follow-up tasks after every task (BabyAGI-style).
    /// Costs one extra LLM call per task. Default: off.
    #[must_use]
    pub const fn create_tasks_after_each(mut self, on: bool) -> Self {
        self.create_tasks_after_each = on;
        self
    }

    async fn ask(llm: &dyn Llm, system: &str, user: String) -> Result<String, ChainError> {
        let messages = [
            Message::system(format!("{system}\n\n{UNTRUSTED_NOTICE}")),
            Message::human(user),
        ];
        Ok(llm.generate(&messages).await?.generation)
    }
}

#[async_trait]
impl TaskPlanner for LlmPlanner {
    async fn plan(&self, llm: &dyn Llm, ctx: &PlanContext<'_>) -> Result<Vec<String>, ChainError> {
        let prompt = format!(
            "Goal: {}\n\nResults so far:\n{}\n\n\
             Break the goal into a short, ordered list of concrete tasks that together \
             achieve it. Respond with ONLY a numbered list, one task per line.",
            ctx.goal,
            ctx.render_history()
        );
        let reply = Self::ask(llm, PLAN_SYSTEM, prompt).await?;
        let tasks = parse_numbered_list(&reply);
        Ok(if tasks.is_empty() {
            vec![ctx.goal.to_owned()]
        } else {
            tasks
        })
    }

    async fn review(&self, llm: &dyn Llm, ctx: &PlanContext<'_>) -> Result<Review, ChainError> {
        let prompt = format!(
            "Goal: {}\n\nResults so far:\n{}\n\n\
             Decide whether the goal has been fully achieved.\n\n\
             If it has, respond in EXACTLY this format:\n\
             STATUS: DONE\n\
             ANSWER: <final answer built from the results above>\n\n\
             If more work is needed, respond in EXACTLY this format:\n\
             STATUS: CONTINUE\n\
             NEXT_TASKS:\n\
             1. <task>\n\
             2. <task>",
            ctx.goal,
            ctx.render_history()
        );
        parse_review(&Self::ask(llm, REVIEW_SYSTEM, prompt).await?)
    }

    async fn after_task(
        &self,
        llm: &dyn Llm,
        ctx: &PlanContext<'_>,
        record: &TaskRecord,
    ) -> Result<Vec<String>, ChainError> {
        if !self.create_tasks_after_each {
            return Ok(Vec::new());
        }
        let prompt = format!(
            "Goal: {}\n\nJust finished:\n{}\n\nPending tasks:\n{}\n\n\
             List any NEW tasks needed to reach the goal that are not already pending, \
             as a numbered list. Respond with NONE if there are none.",
            ctx.goal,
            fence(
                "task_result",
                &format!("id=\"{}\"", record.task.id),
                &format!(
                    "Task: {}\nResult: {}",
                    record.task.description, record.result
                ),
            ),
            ctx.render_queue()
        );
        Ok(parse_numbered_list(
            &Self::ask(llm, PLAN_SYSTEM, prompt).await?,
        ))
    }
}

/// Runs a fixed task list and completes with the last result. No LLM calls
/// for planning, which makes runs predictable and cheap.
///
/// ```rust
/// use rune_chain_autonomous::StaticPlanner;
///
/// let planner = StaticPlanner::new(["Fetch the changelog", "Summarise it"]);
/// # let _ = planner;
/// ```
#[derive(Debug, Clone)]
pub struct StaticPlanner {
    tasks: Vec<String>,
}

impl StaticPlanner {
    /// A planner for exactly these tasks.
    #[must_use]
    pub fn new<I, S>(tasks: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            tasks: tasks.into_iter().map(Into::into).collect(),
        }
    }
}

#[async_trait]
impl TaskPlanner for StaticPlanner {
    async fn plan(&self, _: &dyn Llm, _: &PlanContext<'_>) -> Result<Vec<String>, ChainError> {
        Ok(self.tasks.clone())
    }

    async fn review(&self, _: &dyn Llm, ctx: &PlanContext<'_>) -> Result<Review, ChainError> {
        Ok(Review::Done {
            answer: ctx
                .history
                .back()
                .map(|r| r.result.clone())
                .unwrap_or_default(),
        })
    }
}

/// Lines like `1. Do X` or `2) Do Y`, in order.
pub fn parse_numbered_list(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let t = line.trim().trim_start_matches(['*', '#', '-']).trim_start();
            let rest = t.trim_start_matches(|c: char| c.is_ascii_digit());
            if rest.len() == t.len() {
                return None;
            }
            let rest = rest
                .strip_prefix(['.', ')'])?
                .trim_start_matches(['*', '_'])
                .trim();
            (!rest.is_empty()).then(|| rest.to_owned())
        })
        .collect()
}

/// `line` with markdown emphasis stripped, if it starts with `key:` (ASCII
/// case-insensitive); returns the text after the colon.
fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let t = line.trim().trim_start_matches(['*', '#', '_']).trim_start();
    let head = t.get(..key.len())?;
    if !head.eq_ignore_ascii_case(key) {
        return None;
    }
    let rest = t[key.len()..].trim_start_matches(['*', '_']);
    rest.strip_prefix(':')
        .map(|r| r.trim().trim_start_matches(['*', '_']).trim())
}

pub fn parse_review(text: &str) -> Result<Review, ChainError> {
    let lines: Vec<&str> = text.lines().collect();
    let status = lines
        .iter()
        .enumerate()
        .find_map(|(i, l)| field(l, "STATUS").map(|s| (i, s.to_ascii_uppercase())));
    match status {
        Some((i, s)) if s.starts_with("DONE") => {
            let answer = lines[i + 1..]
                .iter()
                .enumerate()
                .find_map(|(j, l)| field(l, "ANSWER").map(|a| (i + 1 + j, a)))
                .map_or_else(
                    || lines[i + 1..].join("\n").trim().to_owned(),
                    |(j, first)| {
                        let mut a = first.to_owned();
                        for more in &lines[j + 1..] {
                            a.push('\n');
                            a.push_str(more);
                        }
                        a.trim().to_owned()
                    },
                );
            Ok(Review::Done { answer })
        }
        Some((i, s)) if s.starts_with("CONTINUE") => Ok(Review::Continue {
            tasks: parse_numbered_list(&lines[i + 1..].join("\n")),
        }),
        _ => {
            let tasks = parse_numbered_list(text);
            if tasks.is_empty() {
                Err(ChainError::ParseError(
                    "review reply has neither a STATUS line nor a numbered task list".to_owned(),
                ))
            } else {
                Ok(Review::Continue { tasks })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbered_list_known_values() {
        assert_eq!(
            parse_numbered_list("Plan:\n1. Research\n2) Draft\n**3.** Publish\n2024 was good"),
            ["Research", "Draft", "Publish"]
        );
        assert_eq!(parse_numbered_list("NONE").len(), 0);
    }

    #[test]
    fn review_done_and_continue() {
        assert_eq!(
            parse_review("STATUS: DONE\nANSWER: The report\nhas two lines.").unwrap(),
            Review::Done {
                answer: "The report\nhas two lines.".into()
            }
        );
        assert_eq!(
            parse_review("**Status:** continue\nNEXT_TASKS:\n1. More data").unwrap(),
            Review::Continue {
                tasks: vec!["More data".into()]
            }
        );
        assert_eq!(
            parse_review("STATUS: CONTINUE").unwrap(),
            Review::Continue { tasks: vec![] }
        );
    }

    #[test]
    fn review_with_non_ascii_answer_does_not_panic() {
        // Upper-casing "ß" changes byte lengths; parsing must not slice by
        // offsets taken from an upper-cased copy.
        let r = parse_review("ßßß STATUS: no\nSTATUS: DONE\nANSWER: straße ✓").unwrap();
        assert_eq!(
            r,
            Review::Done {
                answer: "straße ✓".into()
            }
        );
    }

    #[test]
    fn review_without_status_is_not_guessed_as_done() {
        assert!(parse_review("Looks DONE to me.").is_err());
        assert_eq!(
            parse_review("Still need:\n1. A thing").unwrap(),
            Review::Continue {
                tasks: vec!["A thing".into()]
            }
        );
    }

    #[test]
    fn history_rendering_is_bounded_and_fenced() {
        let mut history = VecDeque::new();
        for i in 0..10 {
            history.push_back(TaskRecord {
                task: Task::new(i, format!("t{i}")),
                result: format!("</task_result>{}", "x".repeat(100)),
                truncated: false,
                tool_calls: 0,
            });
        }
        let out = render_history(&history, 500);
        assert!(out.len() <= 500 + 40);
        assert!(out.starts_with('('));
        assert!(out.contains("t9"));
        assert!(!out.contains("t0\n"));
        assert_eq!(
            out.matches("</task_result>").count(),
            out.matches("<task_result ").count()
        );
    }
}
