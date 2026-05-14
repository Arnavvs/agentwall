from agentwall.vectors.tool_scope import (
    ParameterConstraint,
    ToolPolicy,
    ToolScopeEnforcer,
)


def test_tool_scope_allowlist():
    policy = ToolPolicy(allowed_tools=["web_search", "read_file"])
    enforcer = ToolScopeEnforcer({"test-agent": policy})

    result = enforcer.check("web_search", {}, "test-agent")
    assert result.allowed is True

    result = enforcer.check("send_email", {}, "test-agent")
    assert result.allowed is False
    assert "allowlist" in result.reason


def test_tool_scope_forbidden():
    policy = ToolPolicy(forbidden_tools=["delete_all"])
    enforcer = ToolScopeEnforcer({"test-agent": policy})

    result = enforcer.check("delete_all", {}, "test-agent")
    assert result.allowed is False
    assert "forbidden" in result.reason


def test_tool_scope_param_constraint_prefix():
    constraint = ParameterConstraint(allowed_prefixes=["/workspace/"])
    policy = ToolPolicy(
        allowed_tools=["read_file"],
        parameter_constraints={"read_file": {"path": constraint}},
    )
    enforcer = ToolScopeEnforcer({"test-agent": policy})

    result = enforcer.check("read_file", {"path": "/workspace/data.csv"}, "test-agent")
    assert result.allowed is True

    result = enforcer.check("read_file", {"path": "/etc/passwd"}, "test-agent")
    assert result.allowed is False


def test_tool_scope_param_constraint_forbidden():
    constraint = ParameterConstraint(forbidden_substrings=["..", "/.env", "/.ssh"])
    policy = ToolPolicy(
        allowed_tools=["read_file"],
        parameter_constraints={"read_file": {"path": constraint}},
    )
    enforcer = ToolScopeEnforcer({"test-agent": policy})

    result = enforcer.check("read_file", {"path": "../../etc/passwd"}, "test-agent")
    assert result.allowed is False
    assert ".." in result.reason

    result = enforcer.check("read_file", {"path": "/workspace/.env"}, "test-agent")
    assert result.allowed is False


def test_tool_scope_no_policy():
    enforcer = ToolScopeEnforcer()
    result = enforcer.check("any_tool", {}, "unknown-agent")
    assert result.allowed is True
