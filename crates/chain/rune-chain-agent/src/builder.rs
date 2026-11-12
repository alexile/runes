//! Builder methods shared by both agents (they differ only in the loop).

macro_rules! toolbox_builder {
    () => {
        /// Register a tool the agent may call.
        #[must_use]
        pub fn tool(mut self, tool: impl rune_chain_core::Tool + 'static) -> Self {
            self.toolbox.add(std::sync::Arc::new(tool), false);
            self
        }

        /// Register a tool that only runs after the [`Approver`](crate::Approver)
        /// allows it. Without an approver every call to it is denied.
        #[must_use]
        pub fn tool_requiring_approval(
            mut self,
            tool: impl rune_chain_core::Tool + 'static,
        ) -> Self {
            self.toolbox.add(std::sync::Arc::new(tool), true);
            self
        }

        /// Register already-boxed tools, e.g. `rune_chain_tools::describe::all()`.
        #[must_use]
        pub fn tools(
            mut self,
            tools: impl IntoIterator<Item = Box<dyn rune_chain_core::Tool>>,
        ) -> Self {
            for tool in tools {
                self.toolbox.add(std::sync::Arc::from(tool), false);
            }
            self
        }

        /// Set the maximum number of tool-call rounds (shorthand for
        /// [`AgentLimits::max_iterations`](crate::AgentLimits::max_iterations)).
        #[must_use]
        pub const fn max_iterations(mut self, max: usize) -> Self {
            self.toolbox.limits.max_iterations = max;
            self
        }

        /// Replace all resource limits.
        #[must_use]
        pub const fn limits(mut self, limits: crate::AgentLimits) -> Self {
            self.toolbox.limits = limits;
            self
        }

        /// Choose what happens when a tool call fails (default:
        /// [`ToolErrorMode::ReturnToModel`](crate::ToolErrorMode::ReturnToModel)).
        #[must_use]
        pub const fn tool_error_mode(mut self, mode: crate::ToolErrorMode) -> Self {
            self.toolbox.error_mode = mode;
            self
        }

        /// Wrap tool output in `<tool_output>` fences and tell the model in the
        /// system prompt that fenced text is untrusted data (default: on).
        ///
        /// Turning this off feeds raw tool output to the model; only do so for
        /// tools whose output you fully control.
        #[must_use]
        pub const fn fence_tool_outputs(mut self, on: bool) -> Self {
            self.toolbox.fence_outputs = on;
            self
        }

        /// Set the approver consulted for tools registered with
        /// [`tool_requiring_approval`](Self::tool_requiring_approval).
        #[must_use]
        pub fn approver(mut self, approver: impl crate::Approver + 'static) -> Self {
            self.toolbox.set_approver(std::sync::Arc::new(approver));
            self
        }

        /// Receive an [`AgentEvent`](crate::AgentEvent) for every step, tool
        /// call, tool result and the final answer.
        #[must_use]
        pub fn on_event(mut self, observer: impl crate::AgentObserver + 'static) -> Self {
            self.toolbox.set_observer(std::sync::Arc::new(observer));
            self
        }

        /// The limits in force.
        #[must_use]
        pub const fn current_limits(&self) -> &crate::AgentLimits {
            &self.toolbox.limits
        }
    };
}

pub(crate) use toolbox_builder;
