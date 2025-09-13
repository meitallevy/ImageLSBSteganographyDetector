PYTHON_CODE_PATTERNS = [
    r'\bdef\b', r'\bclass\b', r'\bimport\b', r'\bfrom\b',
    r'\bprint\s*\(', r'\breturn\b', r'\bif\b', r'\belse\b', r'\belif\b',
    r'\bfor\b', r'\bwhile\b', r'\btry\b', r'\bexcept\b', r'\bwith\b',
    r'\blambda\b', r'\bassert\b', r'\bpass\b', r'\bbreak\b', r'\bcontinue\b',
    r'#[^\n]*', r'""".*?"""', r"'''.*?'''"
]

JS_CODE_PATTERNS = [
    r'\bfunction\b',  # function declaration
    r'\bvar\b', r'\blet\b', r'\bconst\b',  # variable declarations
    r'\bconsole\.log\b',  # console output
    r'\bdocument\.getElementById\b',  # DOM access
    r'\bwindow\.',  # window object access
    r'\balert\s*\(',  # alert function
    r'\breturn\b',  # return statements
    r'\bif\b', r'\belse\b', r'\bfor\b', r'\bwhile\b', r'\bswitch\b', r'\bcase\b',  # control flow
    r'\btry\b', r'\bcatch\b', r'\bfinally\b',
    r'\beval\s*\(',  # dangerous JS eval
    r'\bFunction\s*\(',  # dynamic JS function
    r'document\.write\s*\(',  # document write
    r'\bsetTimeout\s*\(', r'\bsetInterval\s*\('
]

DANGEROUS_FUNCTION_PATTERNS = [
    r'\bexec\s*\(', r'\beval\s*\(', r'\bcompile\s*\(',
    r'\bopen\s*\([^)]*["\']w', r'\bos\.system\s*\(', r'\bsubprocess\.',
    r'\bpopen\s*\(', r'\binput\s*\(', r'\b__import__\s*\(', r'\bpickle\.loads\s*\(',
    r'\bsocket\.socket\s*\(', r'\bshlex\.split\s*\(', r'\bthreading\.Thread\s*\(',
    r'\bctypes\.', r'\bmarshal\.loads\s*\(', r'\bos\.remove\s*\(', r'\bos\.unlink\s*\(',
    r'\bos\.rmdir\s*\(', r'\bos\.mkdir\s*\(', r'\bdocument\.write\s*\(', r'\bFunction\s*\('
]

ALL_CODE_PATTERNS = PYTHON_CODE_PATTERNS + JS_CODE_PATTERNS
