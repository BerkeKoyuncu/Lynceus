import unittest
import traceback
import sys
from test_2fa_logic import Test2FAEnforcement

suite = unittest.TestSuite()
suite.addTest(Test2FAEnforcement('test_complete_2fa_flow'))

result = unittest.TestResult()
suite.run(result)

with open('scratch/clean_output.txt', 'w', encoding='utf-8') as f:
    if result.wasSuccessful():
        f.write("SUCCESS\n")
    else:
        f.write("FAILED\n")
        for test, err in result.failures + result.errors:
            f.write(f"Error in test: {test}\n")
            f.write(err + "\n")
print("Run complete.")
