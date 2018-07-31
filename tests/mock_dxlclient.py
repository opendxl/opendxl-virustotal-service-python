class MockDxlClient(object):

    latest_sent_message = ""

    def send_response(self, response):
        self.latest_sent_message = response
