class ExtractionReport:
    def __init__(self, mode):
        self.extraction_mode = mode
        self.preview_text = ""
        self.code_matches = []
        self.dangerous_function_matches = []
        self.is_suspicious = False

    def summarize(self):
        self.is_suspicious = bool(self.code_matches or self.dangerous_function_matches)


class ExtractionReportCollectionForImage:
    def __init__(self, image_path):
        self.image_path = image_path
        self.mode_reports = []

    def add_mode_report(self, report: ExtractionReport):
        self.mode_reports.append(report)
