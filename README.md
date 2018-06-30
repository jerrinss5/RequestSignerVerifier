# RequestSignerVerifier
An application to verify request going through firewall or any system and being verified at AWS API Gateway

Why need for request signer and verifier
AWS Lambda functions can be invoked by few different sources: https://docs.aws.amazon.com/lambda/latest/dg/invoking-lambda-function.html

If AWS Lambda function is triggered by AWS API Gateway then AWS API Gateway endpoint needs to be publicly accessible to access the lambda functions in the system.

If there is a firewall sitting in front of the address resolution system and your requirement is that all the traffic reaching the lambda function should traverse through it is currently not possible [06.29.18]

To achieve this this request signer verifier service can be used where the verifier is attached to the AWS API Gateway and can do code and policy validation at that point.

Diagram:

Route 53 -> Firewall System -> AWS API Gateway Endpoint (Publicly accessible) -> Lambda functions

Problem with the above approach:
Anybody with intention to bypass the firewall system can do tracert to find out the IP or the url of the AWS API Gateway endpoint which is publicly accessible and directly pass the request to it.

Solution Diagram:

Route 53 -> Firewall System -> Request Signer Service -> AWS API Gateway Endpoint with Lambda Verifier service -> Lambda function

Problems resolved:
Attacker trying to bypass the firewall and calling the AWS API Gateway endpoint would be denied access and "Request did not come from a valid source" would be logged, since the attacker did not have the header with the signature and timestamp for that request.

Attacker trying to replay an old message would also be denied as there is a configurable time window and if the request is older than the configurable time window then it would be denied and "Request came from a valid source but was an old request" would be logged


Pros:
. Prevents bypassing firewall system mitigating potential SQLi, Server Side Forgery, etc attacks,
. Signature structure prevents - replay and modification attacks to the payload.
. Can enforce TLSv1.2 connection to AWS API Gateway as it is currently not enforced. [06.29.18]

Improvements that can be added:
. Program can be written in GO to improve the performance as every request for this lambda function would be going through the flow.
. Signer verifier performance can be improved using MAC(Message authentication code).
. Currently using timeout of 2sec in the request signer service to identify if the firewall system has finished sending data to it, and can be replaced by better means.