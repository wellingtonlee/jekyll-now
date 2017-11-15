---
layout: post
title: Checking for Valid Parentheses
tags: 
- programming
---

A quick writeup on how to check if a string has valid parentheses. The easiest way to implement this is with a stack. In python, we use a list as a stack (`append()` behaves like `push()`):

**checkParentheses.py**
---

```python
class CheckParentheses(object):
    def checkValidAmount(self, s):
        if s.count('(') != s.count(')') or s.count('{') != s.count('}') or s.count('[') != s.count(']'):
            return False
        return True
    
    def isValid(self, s):
        if not self.checkValidAmount(s):
            return False
        
        stack = []
        
        for c in s:
            if c in ['(', '{', '[']:
                stack.append(c)
            else:
                res = stack.pop()
                if (c == ')' and res != '(') or (c == '}' and res != '{') or (c == ']' and res != '['):
                    return False
        
        return True
```
