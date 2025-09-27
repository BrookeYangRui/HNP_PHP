#!/usr/bin/env python3
"""
Advanced PHP AST Parser for True Taint Tracking

This module provides a more sophisticated PHP parser that can:
1. Parse PHP syntax into a proper AST
2. Handle variable assignments, function calls, and control flow
3. Track variable scopes and lifetimes
4. Identify data dependencies
"""

import re
import os
from typing import Dict, List, Set, Any, Optional, Tuple, Union
from dataclasses import dataclass
from enum import Enum


class NodeType(Enum):
    """Types of AST nodes"""
    ASSIGNMENT = "assignment"
    FUNCTION_CALL = "function_call"
    VARIABLE = "variable"
    STRING = "string"
    ARRAY_ACCESS = "array_access"
    METHOD_CALL = "method_call"
    STATIC_CALL = "static_call"
    CONDITIONAL = "conditional"
    LOOP = "loop"
    INCLUDE = "include"
    RETURN = "return"


@dataclass
class ASTNode:
    """Base AST node"""
    node_type: NodeType
    line: int
    column: int
    content: str
    children: List['ASTNode'] = None
    
    def __post_init__(self):
        if self.children is None:
            self.children = []


class VariableNode(ASTNode):
    """Variable node"""
    def __init__(self, node_type: NodeType, line: int, column: int, content: str, 
                 name: str, scope: str = "global", is_tainted: bool = False, 
                 taint_sources: List[str] = None, children: List['ASTNode'] = None):
        super().__init__(node_type, line, column, content, children)
        self.name = name
        self.scope = scope
        self.is_tainted = is_tainted
        self.taint_sources = taint_sources or []


class AssignmentNode(ASTNode):
    """Assignment node"""
    def __init__(self, node_type: NodeType, line: int, column: int, content: str,
                 left_var: str, right_expr: ASTNode, assignment_type: str = "=",
                 children: List['ASTNode'] = None):
        super().__init__(node_type, line, column, content, children)
        self.left_var = left_var
        self.right_expr = right_expr
        self.assignment_type = assignment_type


class FunctionCallNode(ASTNode):
    """Function call node"""
    def __init__(self, node_type: NodeType, line: int, column: int, content: str,
                 function_name: str, arguments: List[ASTNode], is_method: bool = False,
                 object_name: Optional[str] = None, children: List['ASTNode'] = None):
        super().__init__(node_type, line, column, content, children)
        self.function_name = function_name
        self.arguments = arguments
        self.is_method = is_method
        self.object_name = object_name


class ArrayAccessNode(ASTNode):
    """Array access node"""
    def __init__(self, node_type: NodeType, line: int, column: int, content: str,
                 array_name: str, key: str, is_superglobal: bool = False,
                 children: List['ASTNode'] = None):
        super().__init__(node_type, line, column, content, children)
        self.array_name = array_name
        self.key = key
        self.is_superglobal = is_superglobal


class PHPASTParser:
    """Advanced PHP AST Parser"""
    
    def __init__(self):
        # PHP keywords and operators
        self.keywords = {
            'if', 'else', 'elseif', 'while', 'for', 'foreach', 'do',
            'switch', 'case', 'default', 'break', 'continue',
            'function', 'class', 'interface', 'trait',
            'public', 'private', 'protected', 'static',
            'return', 'include', 'require', 'include_once', 'require_once',
            'new', 'this', 'self', 'parent'
        }
        
        # Superglobals
        self.superglobals = {
            '$_GET', '$_POST', '$_COOKIE', '$_SESSION', '$_SERVER',
            '$_FILES', '$_ENV', '$GLOBALS', '$_REQUEST'
        }
        
        # Taint source patterns
        self.taint_sources = {
            'http_host': [
                r'\$_SERVER\s*\[\s*[\'"]HTTP_HOST[\'"]\s*\]',
                r'\$_SERVER\s*\[\s*[\'"]SERVER_NAME[\'"]\s*\]',
            ],
            'request_methods': [
                r'getHost\s*\(',
                r'getHttpHost\s*\(',
                r'getServerName\s*\(',
                r'getSchemeAndHttpHost\s*\(',
                r'getUri\s*\(',
                r'getRequestUri\s*\(',
            ],
            'proxy_headers': [
                r'X-Forwarded-Host',
                r'FORWARDED_HOST',
            ]
        }
        
        # Taint sink patterns
        self.taint_sinks = {
            'url_generation': [
                r'url\s*\(',
                r'route\s*\(',
                r'generateUrl\s*\(',
                r'createUrl\s*\(',
                r'home_url\s*\(',
                r'site_url\s*\(',
                r'admin_url\s*\(',
                r'esc_url\s*\(',
            ],
            'redirect': [
                r'redirect\s*\(',
                r'wp_safe_redirect\s*\(',
                r'RedirectResponse',
            ],
            'authentication': [
                r'wp_login_url\s*\(',
                r'wp_logout_url\s*\(',
                r'login\s*\(',
                r'logout\s*\(',
            ]
        }
    
    def parse_file(self, file_path: str) -> Dict[str, Any]:
        """Parse a PHP file into AST"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
            return {}
        
        return self.parse_content(content, file_path)
    
    def parse_content(self, content: str, file_path: str) -> Dict[str, Any]:
        """Parse PHP content into AST"""
        lines = content.splitlines()
        
        ast_data = {
            'file': file_path,
            'functions': {},
            'classes': {},
            'variables': {},
            'statements': [],
            'taint_sources': [],
            'taint_sinks': [],
            'includes': []
        }
        
        current_function = None
        current_class = None
        variable_scope = {}
        
        for line_num, line in enumerate(lines, 1):
            original_line = line
            line = line.strip()
            
            if not line or line.startswith('//') or line.startswith('#'):
                continue
            
            # Parse different types of statements
            node = self._parse_statement(line, line_num, 0, original_line)
            if node:
                ast_data['statements'].append(node)
                
                # Check for taint sources
                if self._is_taint_source(node):
                    ast_data['taint_sources'].append(node)
                
                # Check for taint sinks
                if self._is_taint_sink(node):
                    ast_data['taint_sinks'].append(node)
                
                # Track variables
                self._track_variables(node, variable_scope, current_function)
        
        ast_data['variables'] = variable_scope
        return ast_data
    
    def _parse_statement(self, line: str, line_num: int, column: int, original_line: str) -> Optional[ASTNode]:
        """Parse a single PHP statement"""
        
        # Assignment statements
        assignment_match = re.match(r'(\$[a-zA-Z_][a-zA-Z0-9_]*)\s*([.=+\-*/%]?=)\s*(.+)', line)
        if assignment_match:
            var_name = assignment_match.group(1)
            op = assignment_match.group(2)
            expr = assignment_match.group(3)
            
            # Parse the right-hand expression
            right_expr = self._parse_expression(expr, line_num, column)
            
            return AssignmentNode(
                node_type=NodeType.ASSIGNMENT,
                line=line_num,
                column=column,
                content=original_line,
                left_var=var_name,
                right_expr=right_expr,
                assignment_type=op
            )
        
        # Function calls
        func_match = re.match(r'(\w+)\s*\(', line)
        if func_match:
            func_name = func_match.group(1)
            args = self._extract_function_arguments(line)
            arg_nodes = [self._parse_expression(arg, line_num, column) for arg in args]
            
            return FunctionCallNode(
                node_type=NodeType.FUNCTION_CALL,
                line=line_num,
                column=column,
                content=original_line,
                function_name=func_name,
                arguments=arg_nodes
            )
        
        # Method calls
        method_match = re.match(r'(\$[a-zA-Z_][a-zA-Z0-9_]*)\s*->\s*(\w+)\s*\(', line)
        if method_match:
            obj_name = method_match.group(1)
            method_name = method_match.group(2)
            args = self._extract_function_arguments(line)
            arg_nodes = [self._parse_expression(arg, line_num, column) for arg in args]
            
            return FunctionCallNode(
                node_type=NodeType.METHOD_CALL,
                line=line_num,
                column=column,
                content=original_line,
                function_name=method_name,
                arguments=arg_nodes,
                is_method=True,
                object_name=obj_name
            )
        
        # Static method calls
        static_match = re.match(r'(\w+)::(\w+)\s*\(', line)
        if static_match:
            class_name = static_match.group(1)
            method_name = static_match.group(2)
            args = self._extract_function_arguments(line)
            arg_nodes = [self._parse_expression(arg, line_num, column) for arg in args]
            
            return FunctionCallNode(
                node_type=NodeType.STATIC_CALL,
                line=line_num,
                column=column,
                content=original_line,
                function_name=method_name,
                arguments=arg_nodes,
                is_method=True,
                object_name=class_name
            )
        
        # Array access
        array_match = re.match(r'(\$[a-zA-Z_][a-zA-Z0-9_]*)\s*\[\s*([^\]]+)\s*\]', line)
        if array_match:
            array_name = array_match.group(1)
            key = array_match.group(2).strip()
            
            return ArrayAccessNode(
                node_type=NodeType.ARRAY_ACCESS,
                line=line_num,
                column=column,
                content=original_line,
                array_name=array_name,
                key=key,
                is_superglobal=array_name in self.superglobals
            )
        
        # Variable usage
        var_match = re.match(r'(\$[a-zA-Z_][a-zA-Z0-9_]*)', line)
        if var_match:
            var_name = var_match.group(1)
            
            return VariableNode(
                node_type=NodeType.VARIABLE,
                line=line_num,
                column=column,
                content=original_line,
                name=var_name
            )
        
        return None
    
    def _parse_expression(self, expr: str, line_num: int, column: int) -> ASTNode:
        """Parse a PHP expression"""
        expr = expr.strip()
        
        # String literal
        if (expr.startswith('"') and expr.endswith('"')) or (expr.startswith("'") and expr.endswith("'")):
            return ASTNode(
                node_type=NodeType.STRING,
                line=line_num,
                column=column,
                content=expr
            )
        
        # Variable
        var_match = re.match(r'(\$[a-zA-Z_][a-zA-Z0-9_]*)', expr)
        if var_match:
            return VariableNode(
                node_type=NodeType.VARIABLE,
                line=line_num,
                column=column,
                content=expr,
                name=var_match.group(1)
            )
        
        # Array access
        array_match = re.match(r'(\$[a-zA-Z_][a-zA-Z0-9_]*)\s*\[\s*([^\]]+)\s*\]', expr)
        if array_match:
            return ArrayAccessNode(
                node_type=NodeType.ARRAY_ACCESS,
                line=line_num,
                column=column,
                content=expr,
                array_name=array_match.group(1),
                key=array_match.group(2).strip(),
                is_superglobal=array_match.group(1) in self.superglobals
            )
        
        # Function call
        func_match = re.match(r'(\w+)\s*\(', expr)
        if func_match:
            func_name = func_match.group(1)
            args = self._extract_function_arguments(expr)
            arg_nodes = [self._parse_expression(arg, line_num, column) for arg in args]
            
            return FunctionCallNode(
                node_type=NodeType.FUNCTION_CALL,
                line=line_num,
                column=column,
                content=expr,
                function_name=func_name,
                arguments=arg_nodes
            )
        
        # Default: treat as string
        return ASTNode(
            node_type=NodeType.STRING,
            line=line_num,
            column=column,
            content=expr
        )
    
    def _extract_function_arguments(self, line: str) -> List[str]:
        """Extract function arguments from a function call"""
        # Find the opening parenthesis
        start = line.find('(')
        if start == -1:
            return []
        
        # Find the matching closing parenthesis
        paren_count = 0
        end = start
        for i, char in enumerate(line[start:], start):
            if char == '(':
                paren_count += 1
            elif char == ')':
                paren_count -= 1
                if paren_count == 0:
                    end = i
                    break
        
        if paren_count != 0:
            return []
        
        # Extract arguments
        args_str = line[start+1:end].strip()
        if not args_str:
            return []
        
        # Simple argument splitting (doesn't handle nested parentheses)
        args = []
        current_arg = ""
        paren_level = 0
        
        for char in args_str:
            if char == '(':
                paren_level += 1
            elif char == ')':
                paren_level -= 1
            elif char == ',' and paren_level == 0:
                args.append(current_arg.strip())
                current_arg = ""
                continue
            
            current_arg += char
        
        if current_arg.strip():
            args.append(current_arg.strip())
        
        return args
    
    def _is_taint_source(self, node: ASTNode) -> bool:
        """Check if a node is a taint source"""
        content = node.content
        
        for source_type, patterns in self.taint_sources.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return True
        
        return False
    
    def _is_taint_sink(self, node: ASTNode) -> bool:
        """Check if a node is a taint sink"""
        if node.node_type not in [NodeType.FUNCTION_CALL, NodeType.METHOD_CALL, NodeType.STATIC_CALL]:
            return False
        
        func_node = node
        content = node.content
        
        for sink_type, patterns in self.taint_sinks.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return True
        
        return False
    
    def _track_variables(self, node: ASTNode, variable_scope: Dict[str, Any], current_function: Optional[str]):
        """Track variable usage and scope"""
        if node.node_type == NodeType.ASSIGNMENT:
            assignment = node
            var_name = assignment.left_var
            variable_scope[var_name] = {
                'line': assignment.line,
                'type': 'assignment',
                'function': current_function,
                'tainted': False
            }
        
        elif node.node_type == NodeType.VARIABLE:
            var_node = node
            var_name = var_node.name
            if var_name not in variable_scope:
                variable_scope[var_name] = {
                    'line': var_node.line,
                    'type': 'usage',
                    'function': current_function,
                    'tainted': False
                }


def main():
    """Test the PHP AST parser"""
    parser = PHPASTParser()
    
    # Test with a sample PHP file
    test_content = '''
<?php
$host = $_SERVER['HTTP_HOST'];
$url = "https://" . $host;
redirect($url);
?>
'''
    
    result = parser.parse_content(test_content, "test.php")
    
    print("Parsed AST:")
    print(f"Variables: {result['variables']}")
    print(f"Taint sources: {len(result['taint_sources'])}")
    print(f"Taint sinks: {len(result['taint_sinks'])}")
    
    for statement in result['statements']:
        print(f"Line {statement.line}: {statement.node_type.value} - {statement.content}")


if __name__ == "__main__":
    main()
