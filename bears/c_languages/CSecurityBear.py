from coalib.bearlib.abstractions.Linter import linter
from coalib.results.RESULT_SEVERITY import RESULT_SEVERITY
from coalib.settings.Setting import typed_list


@linter(executable="flawfinder", output_format="regex",
        output_regex=r'.+:(?P<line>\d+):(?P<column>\d+):\s*'
                     r'\[(?P<severity>\d)\]\s*'
                     r'\((?P<origin>.+)\) (?P<message>.+)',
        severity_map={"5": RESULT_SEVERITY.MAJOR,
                      "4": RESULT_SEVERITY.NORMAL, "3": RESULT_SEVERITY.NORMAL,
                      "2": RESULT_SEVERITY.INFO, "1": RESULT_SEVERITY.INFO})
class CSecurityBear:
    """
    Report possible security weaknesses for C/C++.

    For more information, consult <http://www.dwheeler.com/flawfinder/>.
    """

    LANGUAGES = "C", "C++"

    @staticmethod
    def create_arguments(filename, file, config_file,
                         exclude_likely_false_positives: bool=True,
                         flawfinder_rules: typed_list(int)=[]):
        """
        :param exclude_likely_false_positives:
            Exclude results that are likely to be false positives.
        :param flawfinder_rules:
            A list of CWE numbers. Only results for those CWEs will be shown. To
            show e.g. only CWE-78, simply give the ``78`` as a value.
        """
        args = "--columns", "--dataonly", "--quiet", "--singleline"

        if exclude_likely_false_positives:
            args += ('--falsepositive',)

        if flawfinder_rules:
            args += "--regex", "|".join("CWE-"+str(rule)
                                        for rule in flawfinder_rules)

        return args + (filename,)
