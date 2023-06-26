import grpc

from messenger.api.v1.greeting_pb2 import GreetingRequest, GreetingResponse
from messenger.api.v1.greeting_pb2_grpc import GreetingServiceServicer, add_GreetingServiceServicer_to_server


class GreetingService(GreetingServiceServicer):

    def SayHello(self, request: GreetingRequest, context: grpc.ServicerContext) -> GreetingResponse:
        return GreetingResponse(message=f'Hello {request.name}!')


def grpc_handlers(server):
    add_GreetingServiceServicer_to_server(GreetingService(), server)
