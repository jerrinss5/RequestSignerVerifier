from __future__ import print_function

import re, base64, os, logging, time, base64

# python library for hashing
from Crypto.Hash import SHA256

# RSA library
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def handler(event, context):
    logger.info('Start authorization Verification flow')
    principalId = 'user|a1b2c3d4'

    ''' Custom code for basic authentication and OAuth2 token validation '''

    # TODO handle if there is no header return null
    try:
        logger.info('Event: %s ' % event)

        # creating instance of custom policy handler class
        allowOrDeny = AllowOrDenyPolicy()

        # getting time stamp and signature from header
        if 'authorizationToken' in event:
            authorization_token = str(event['authorizationToken'])
            server_timestamp, signature_str = authorization_token.split(',')
        else:
            logger.info('Timestamp/Signature header is missing')
            raise Exception('Timestamp/Signature header is missing')

        logger.info('Verification flow started')

        # getting current time stamp
        current_time = int(time.time())

        # checking if the request is new by taking difference
        diff_value = current_time - int(server_timestamp)

        # assigning default freshness to false
        fresh = False

        if diff_value > 5:
            fresh = False
            #TODO to improve performance can end the program at this condition
            # raise exception saying request is old
        else:
            fresh = True

        # converting the signature string to tuple
        signature_decoded = base64.b64decode(signature_str)

        # reading public key from environment variables
        public_key_env = """-----BEGIN PUBLIC KEY-----
-----END PUBLIC KEY-----"""

        public_key = RSA.importKey(str(public_key_env))

        # default deny login
        allow_login = False

        # reading the body of the request
        if 'Body' in event:
            # for requests with data
            post_body = event['Body']
        else:
            # for GET requests
            post_body = ""

        # hashing the request body
        hash_body = (post_body + str(server_timestamp)).encode('utf-8')

        hash_obj = SHA256.new(hash_body)
        hash_value = hash_obj.hexdigest()

        # verifying if the hash value matches to the signature
        verifier = PKCS1_PSS.new(public_key)
        hash_match = verifier.verify(hash_obj, signature_decoded)

        logger.info(hash_match)
        # for logging purposes
        if hash_match and fresh:
            logger.info('Request came from valid source and is fresh')
            allow_login = True
        elif hash_match:
            logger.info('Request came from a valid source but was an old request')
            allow_login = False
        else:
            logger.info('Request did not come from a valid source')
            allow_login = False

        # checking boolean
        if allow_login:
            # validation passed give back success policy by setting True
            return allowOrDeny.allowOrDenyPolicyMethod(event, principalId, True)
        else:
            # validation failed give back failure policy by setting False
            return allowOrDeny.allowOrDenyPolicyMethod(event, principalId, False)

    except Exception as error:
        logger.info('following error occurred: %s' % error)
        # validation failed give back failure policy by setting False
        return allowOrDeny.allowOrDenyPolicyMethod(event, principalId, False)


class AllowOrDenyPolicy:
    def allowOrDenyPolicyMethod(self, event, principalId, permission):
        tmp = event['methodArn'].split(':')
        apiGatewayArnTmp = tmp[5].split('/')
        awsAccountId = tmp[4]
        logger.info('Auth policy creation')
        policy = AuthPolicy(principalId, awsAccountId)
        policy.restApiId = apiGatewayArnTmp[0]
        policy.region = tmp[3]
        policy.stage = apiGatewayArnTmp[1]
        if permission:
            logger.info('Allowed')
            policy.allowAllMethods()
        else:
            logger.info('Denied')
            policy.denyAllMethods()
        # policy.allowMethod(HttpVerb.GET, '/test')

        # Finally, build the policy
        authResponse = policy.build()

        # new! -- add additional key-value pairs associated with the authenticated principal
        # these are made available by APIGW like so: $context.authorizer.<key>
        # additional context is cached
        context = {
            'key': 'value',  # $context.authorizer.key -> value
            'number': 1,
            'bool': True
        }

        # context['arr'] = ['foo'] <- this is invalid, APIGW will not accept it
        # context['obj'] = {'foo':'bar'} <- also invalid

        authResponse['context'] = context
        logger.info('Auth policy created')
        return authResponse


''' Custom code ends '''

'''
You can send a 401 Unauthorized response to the client by failing like so:

  raise Exception('Unauthorized')

If the token is valid, a policy must be generated which will allow or deny
access to the client. If access is denied, the client will receive a 403
Access Denied response. If access is allowed, API Gateway will proceed with
the backend integration configured on the method that was called.

This function must generate a policy that is associated with the recognized
principal user identifier. Depending on your use case, you might store
policies in a DB, or generate them on the fly.

Keep in mind, the policy is cached for 5 minutes by default (TTL is
configurable in the authorizer) and will apply to subsequent calls to any
method/resource in the RestApi made with the same token.

The example policy below denies access to all resources in the RestApi.
'''


class HttpVerb:
    GET = 'GET'
    POST = 'POST'
    PUT = 'PUT'
    PATCH = 'PATCH'
    HEAD = 'HEAD'
    DELETE = 'DELETE'
    OPTIONS = 'OPTIONS'
    ALL = '*'


class AuthPolicy(object):
    # The AWS account id the policy will be generated for. This is used to create the method ARNs.
    awsAccountId = ''
    # The principal used for the policy, this should be a unique identifier for the end user.
    principalId = ''
    # The policy version used for the evaluation. This should always be '2012-10-17'
    version = '2012-10-17'
    # The regular expression used to validate resource paths for the policy
    pathRegex = '^[/.a-zA-Z0-9-\*]+$'

    '''Internal lists of allowed and denied methods.

    These are lists of objects and each object has 2 properties: A resource
    ARN and a nullable conditions statement. The build method processes these
    lists and generates the approriate statements for the final policy.
    '''
    allowMethods = []
    denyMethods = []

    # The API Gateway API id. By default this is set to '*'
    restApiId = '*'
    # The region where the API is deployed. By default this is set to '*'
    region = '*'
    # The name of the stage used in the policy. By default this is set to '*'
    stage = '*'

    def __init__(self, principal, awsAccountId):
        self.awsAccountId = awsAccountId
        self.principalId = principal
        self.allowMethods = []
        self.denyMethods = []

    def _addMethod(self, effect, verb, resource, conditions):
        '''Adds a method to the internal lists of allowed or denied methods. Each object in
        the internal list contains a resource ARN and a condition statement. The condition
        statement can be null.'''
        if verb != '*' and not hasattr(HttpVerb, verb):
            raise NameError('Invalid HTTP verb ' + verb + '. Allowed verbs in HttpVerb class')
        resourcePattern = re.compile(self.pathRegex)
        if not resourcePattern.match(resource):
            raise NameError('Invalid resource path: ' + resource + '. Path should match ' + self.pathRegex)

        if resource[:1] == '/':
            resource = resource[1:]

        resourceArn = 'arn:aws:execute-api:{}:{}:{}/{}/{}/{}'.format(self.region, self.awsAccountId, self.restApiId,
                                                                     self.stage, verb, resource)

        if effect.lower() == 'allow':
            self.allowMethods.append({
                'resourceArn': resourceArn,
                'conditions': conditions
            })
        elif effect.lower() == 'deny':
            self.denyMethods.append({
                'resourceArn': resourceArn,
                'conditions': conditions
            })

    def _getEmptyStatement(self, effect):
        '''Returns an empty statement object prepopulated with the correct action and the
        desired effect.'''
        statement = {
            'Action': 'execute-api:Invoke',
            'Effect': effect[:1].upper() + effect[1:].lower(),
            'Resource': []
        }

        return statement

    def _getStatementForEffect(self, effect, methods):
        '''This function loops over an array of objects containing a resourceArn and
        conditions statement and generates the array of statements for the policy.'''
        statements = []

        if len(methods) > 0:
            statement = self._getEmptyStatement(effect)

            for curMethod in methods:
                if curMethod['conditions'] is None or len(curMethod['conditions']) == 0:
                    statement['Resource'].append(curMethod['resourceArn'])
                else:
                    conditionalStatement = self._getEmptyStatement(effect)
                    conditionalStatement['Resource'].append(curMethod['resourceArn'])
                    conditionalStatement['Condition'] = curMethod['conditions']
                    statements.append(conditionalStatement)

            if statement['Resource']:
                statements.append(statement)

        return statements

    def allowAllMethods(self):
        '''Adds a '*' allow to the policy to authorize access to all methods of an API'''
        self._addMethod('Allow', HttpVerb.ALL, '*', [])

    def denyAllMethods(self):
        '''Adds a '*' allow to the policy to deny access to all methods of an API'''
        self._addMethod('Deny', HttpVerb.ALL, '*', [])

    def allowMethod(self, verb, resource):
        '''Adds an API Gateway method (Http verb + Resource path) to the list of allowed
        methods for the policy'''
        self._addMethod('Allow', verb, resource, [])

    def denyMethod(self, verb, resource):
        '''Adds an API Gateway method (Http verb + Resource path) to the list of denied
        methods for the policy'''
        self._addMethod('Deny', verb, resource, [])

    def allowMethodWithConditions(self, verb, resource, conditions):
        '''Adds an API Gateway method (Http verb + Resource path) to the list of allowed
        methods and includes a condition for the policy statement. More on AWS policy
        conditions here: http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html#Condition'''
        self._addMethod('Allow', verb, resource, conditions)

    def denyMethodWithConditions(self, verb, resource, conditions):
        '''Adds an API Gateway method (Http verb + Resource path) to the list of denied
        methods and includes a condition for the policy statement. More on AWS policy
        conditions here: http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html#Condition'''
        self._addMethod('Deny', verb, resource, conditions)

    def build(self):
        '''Generates the policy document based on the internal lists of allowed and denied
        conditions. This will generate a policy with two main statements for the effect:
        one statement for Allow and one statement for Deny.
        Methods that includes conditions will have their own statement in the policy.'''
        if ((self.allowMethods is None or len(self.allowMethods) == 0) and
                (self.denyMethods is None or len(self.denyMethods) == 0)):
            raise NameError('No statements defined for the policy')

        policy = {
            'principalId': self.principalId,
            'policyDocument': {
                'Version': self.version,
                'Statement': []
            }
        }

        policy['policyDocument']['Statement'].extend(self._getStatementForEffect('Allow', self.allowMethods))
        policy['policyDocument']['Statement'].extend(self._getStatementForEffect('Deny', self.denyMethods))

        return policy