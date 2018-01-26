"""Select frames"""
from pars_hdlc import parser
import enum
import struct


@enum.unique
class APDU(enum.Enum):
    """Application protocol data unit - APDU"""
    get_request = 192  # GET_Requestd,
    set_request = 193  # SET_Requestd,
    event_notification_request = 194  # IMPLICIT EVENT_NOTIFICATION_Requestd,
    action_request = 195  # ACTION_Requestd,
    get_response = 196  # GET_Response,
    set_response = 197  # SET_Response,
    action_response = 199  # ACTION_Response,
    glo_get_request = 200  # IMPLICIT OCTET STRING,
    glo_set_request = 201  # IMPLICIT OCTET STRING,
    glo_event_notification_request = 202  # IMPLICIT OCTET STRING,
    glo_action_request = 203  # IMPLICIT OCTET STRING,
    glo_get_response = 204  # IMPLICIT OCTET STRING,
    glo_set_response = 205  # IMPLICIT OCTET STRING,
    glo_action_response = 207  # IMPLICIT OCTET STRING,
    aarq = 97
    aare = 96


@enum.unique
class GetResponse(enum.Enum):
    """Detalization get_response"""
    get_response_normal = 1  # IMPLICIT_Get_Response_Normal,
    get_response_with_datablock = 2  # IMPLICIT Get_Response_With_Datablock,
    get_response_with_list = 3  # IMPLICIT Get_Response_With_List


@enum.unique
class SetRequest(enum.Enum):
    """Detalization set_request"""
    set_request_normal = 1  # IMPLICIT Set_Request_Normal,
    set_request_with_first_datablock = 2  # IMPLICIT Set_Request_With_First_Datablock,
    set_request_with_datablock = 3  # IMPLICIT Set_Request_With_Datablock,
    set_request_with_list = 4  # IMPLICIT Set_Request_With_List,
    set_request_with_list_and_first_datablock = 5  # IMPLICIT Set_Request_With_List_And_First_Datablock


@enum.unique
class SetResponse(enum.Enum):
    """Detalization get_response"""
    set_response_normal = 1  # IMPLICIT Set_Response_Normal,
    set_response_datablock = 2  # IMPLICIT Set_Response_Datablock,
    set_response_last_datablock = 3 # IMPLICIT Set_Response_Last_Datablock,
    set_response_last_datablock_with_list = 4  # IMPLICIT Set_Response_Last_Datablock_With_List,
    set_response_with_list = 5  # IMPLICIT Set_Response_With_List


@enum.unique
class GetRequest(enum.Enum):
    """Detalization get_request"""
    get_request_normal = 1  # IMPLICIT Get_Request_Normal,
    get_request_next = 2  # IMPLICIT Get_Request_Next,
    get_request_with_list = 3 # IMPLICIT Get_Request_With_List


@enum.unique
class ActionRequest(enum.Enum):
    """Detalization action_request"""
    action_request_normal  = 1  # IMPLICIT Action_Request_Normal,
    action_request_next_pblock = 2  # IMPLICIT Action_Request_Next_Pblock,
    action_request_with_list = 3  # IMPLICIT Action_Request_With_List,
    action_request_with_first_pblock = 4  # IMPLICIT Action_Request_With_First_Pblock,
    action_request_with_list_and_first_pblock = 5  # IMPLICIT Action_Request_With_List_And_First_Pblock,
    action_request_with_pblock = 6  # IMPLICIT Action_Request_With_Pblock


@enum.unique
class ActionResponse(enum.Enum):
    """Detalization action_response"""
    action_response_normal = 1  # IMPLICIT Action_Response_Normal,
    action_response_with_pblock = 2  # IMPLICIT Action_Response_With_Pblock,
    action_response_with_list = 3  # IMPLICIT Action_Response_With_List,
    action_response_next_pblock = 4  # IMPLICIT Action_Response_Next_Pblock


class ErrorValidationValueLlc(Exception):
    """Raised when llc value is not valid"""
    pass


class ErrorValidationRequestResponse(Exception):
    """Raised when request or response value is not valid"""
    pass


class ErrorValidationPair(Exception):
    """Raised when pair values is not valid"""
    pass


class ErrorDetailReqRsp(Exception):
    """Raised when values detail reqest or response is not valid"""
    pass


according_apdu = {
    APDU.get_request: APDU.get_response,
    APDU.set_request: APDU.set_response,
    APDU.aare: APDU.aarq,
    APDU.action_request: APDU.action_response,
    APDU.glo_action_request: APDU.glo_action_response,
    APDU.glo_set_request: APDU.glo_set_response
}


deatail_apdu = {
    APDU.get_response: GetResponse,
    APDU.set_request: SetRequest,
    APDU.set_response: SetResponse,
    APDU.get_request: GetRequest,
    APDU.action_request: ActionRequest,
    APDU.action_response: ActionResponse
}


class Frames(object):
    """Instanse consists frames list"""
    def __init__(self, load_file):
        self.frames = []
        self.current_item = 0
        for line in load_file:
            if line.startswith('7e') and line.endswith('7e\n'):
                self.frames.append(line)

    def get_frame(self):
        """Return current item frames list"""
        value = self.frames[self.current_item]
        self.current_item += 1
        return value[0:-1]

    def __iter__(self):
        """Overrided magic method __iter__"""
        self.current_item = 0
        return self

    def next(self):
        """Return current item frames list"""
        try:
            value = self.frames[self.current_item]
        except IndexError:
            raise StopIteration
        self.current_item += 1
        return value[0:-1]


def validation_llc(informations):
    """Check first 3 bytes, they shoud were 'e6e600' or 'e6e700"""
    req, rsp = informations
    llc_request = struct.unpack_from('>BBB', req, 0)[0]
    llc_response = struct.unpack_from('>BBB', req, 0)[0]
    if llc_request == 'e6e600'.decode('hex') and llc_response == 'e6e700':
        return True


def validation_pair(request, response):
    """ Check accord pair(response and request)"""
    expected_responce = according_apdu.get(request)
    if expected_responce is not None:
        if expected_responce == response:
            return True
        else:
            raise ErrorValidationPair()


def check_detail_request_response(informations, request, response):
    """Check detalil request and response"""
    req, rsp = informations
    detail_value_apdu_req = struct.unpack_from('>B', req, 4)[0]
    detail_value_apdu_rsp = struct.unpack_from('>B', rsp, 4)[0]
    expected_req = deatail_apdu.get(request)
    expected_res = deatail_apdu.get(response)
    if expected_req is not None or expected_res is not None:
        value_detail_apdu_rsp = deatail_apdu[response]
        value_detail_apdu_req = deatail_apdu[request]
        try:
            request = value_detail_apdu_rsp(detail_value_apdu_req)
            print request
        except Exception as ex:
            print "{}".format(ex)
        try:
            response = value_detail_apdu_req(detail_value_apdu_rsp)
            print response
        except Exception as ex:
            print "{}".format(ex)


def validation_request_response(informations):
    """Validation apdu"""
    req, rsp = informations
    apdu_value1 = struct.unpack_from('>B', req, 3)[0]
    apdu_value2 = struct.unpack_from('>B', rsp, 3)[0]
    request = None
    response = None
    try:
        request = APDU(apdu_value1)
        print request
    except Exception as ex:
        print "{}".format(ex)
    try:
        response = APDU(apdu_value2)
    except Exception as ex:
        print "{}".format(ex)
    if request and response:
        if validation_pair(request, response):
            return request, response
        else:
            raise False


def sort_and_add_frames():
    load_file = open('D2.tpl', 'r')
    frames = Frames(load_file)
    pars = parser.Parser()
    payload = []
    couple_dlms = []
    counter_couple = 0
    for frame in frames:
        if counter_couple <= 1:
            data = pars.get_payload(frame)
            if data.control.command_response == 'I':
                couple_dlms.append(data.information.decode('hex'))
                counter_couple += 1
                if counter_couple == 2:
                    counter_couple = 0
                    payload.append(couple_dlms)
                    couple_dlms = []
    return payload


def validation_payloads(payload):
    for informations in payload:
        value_validation_llc = validation_llc(informations)
        if value_validation_llc is False:
            raise ErrorValidationValueLlc()
        request, response = validation_request_response(informations)
        if request is False:
            raise ErrorValidationRequestResponse()
        detail_apdu = check_detail_request_response(
            informations, request, response
        )
        if detail_apdu is False:
            raise ErrorDetailReqRsp()


if __name__ == '__main__':
    payloads = sort_and_add_frames()
    validation_payloads(payloads)
