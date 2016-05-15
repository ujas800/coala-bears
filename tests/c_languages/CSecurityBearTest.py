from bears.c_languages.CSecurityBear import CSecurityBear
from tests.LocalBearTestHelper import verify_local_bear


good_file = """
void demo() {
    char d[20];  // CWE 119/120, won't be detected with --falsepositive
}""".splitlines(keepends=True)

bad_file = """
void demo(char *a) {
    strcpy(a, '\n');  // CWE 120
}""".splitlines(keepends=True)


CSecurityBearTest = verify_local_bear(CSecurityBear,
                                      valid_files=(good_file,),
                                      invalid_files=(bad_file,))

CSecurityBearFalsePositiveTest = verify_local_bear(
    CSecurityBear, valid_files=(), invalid_files=(good_file, bad_file),
    settings={'exclude_likely_false_positives': 'nope'})

CSecurityBearRulesTest = verify_local_bear(
    CSecurityBear, valid_files=(bad_file,), invalid_files=(good_file,),
    settings={'exclude_likely_false_positives': 'nope',
              'flawfinder_rules': "119, 78"})
