import socket
import webbrowser
import requests
import pkce
import json
import jwt
import random
from addict import Dict

# Place FamilySearch API key here
clientID = ""
devEnvironment = "Production"

# Gloval variables
redirectUri = "http://127.0.0.1:5000"

authIntegration = "https://identint.familysearch.org/cis-web/oauth2/v3/authorization"
authBeta = "https://identbeta.familysearch.org/cis-web/oauth2/v3/authorization"
authProduction = "https://ident.familysearch.org/cis-web/oauth2/v3/authorization"

tokenIntegration = "https://identint.familysearch.org/cis-web/oauth2/v3/token"
tokenBeta = "https://identbeta.familysearch.org/cis-web/oauth2/v3/token"
tokenProduction = "https://ident.familysearch.org/cis-web/oauth2/v3/token"

regIntegration = "https://api-integ.familysearch.org/"
regBeta = "https://apibeta.familysearch.org/"
regProduction = "https://api.familysearch.org/"

tokenDict = Dict()

def CodeToSplit(codeToSplit):
    """Splits a string into two separate pieces to return the second element

    Parameters
        codetoSplit: a string that needs to be split into two

    Return: a string of the second element in the split
    
    """
    codeToSplit = codeToSplit.split("=")
    codeToSplit = codeToSplit[1]
    return codeToSplit

def GetAccessToken(authCode, codeVerifier):
    """Exchanges the FamilySearch authorization code for an access token.

    Parameters
        authCode: a string that contains the FamilySearch authorization code.
        codeVerifier: a string that contains the code verifier for FamilySearch
    """
    global tokenDict

    if (devEnvironment == "Production"):
        tokenBaseUri = tokenProduction
    elif (devEnvironment == "Beta"):
        tokenBaseUri = tokenBeta
    elif (devEnvironment == "Integration"):
        tokenBaseUri = tokenIntegration

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded"
    }

    dataBody = {
        "code": f"{authCode}",
        "grant_type": "authorization_code",
        "client_id": f"{clientID}",
        "code_verifier": f"{codeVerifier}"
        }

    response = requests.post(tokenBaseUri, data=dataBody, headers=headers)

    if (response.status_code == 200):
        jsonDict = json.loads(response.text)
        tokenDict = Dict(jsonDict)

def DecodeJWT():
    """ Decodes the identity token from FamilySearch, and sends a welcome 
    message to a user based on information from the JWT identity token
    """
    # decode identity token
    global tokenDict
    decodedJWT = jwt.decode(tokenDict.id_token, options={"verify_signature": False})
    identityToken = Dict(decodedJWT)

    print("Hello " + identityToken.given_name + "!")
    print()


def GetCurrentUser():
    """Gets the PID for the currently logged in user from FamilySearch
    Return: a dictionary that contains data from FamilySearch
    """
    global tokenDict

    if (devEnvironment == "Production"):
        regularBaseUri = regProduction
    elif (devEnvironment == "Beta"):
        regularBaseUri = regBeta
    elif (devEnvironment == "Integration"):
        regularBaseUri = regIntegration

    apiRoute = "platform/users/current";
    apiRequest = f"{regularBaseUri}{apiRoute}"

    headers = {
        "Accept": "application/json",
        "Authorization": "Bearer " + tokenDict.access_token
    }

    response = requests.get(apiRequest, headers=headers)

    if (response.status_code == 200):
        jsonDict = json.loads(response.text)
        currentUserDict = Dict(jsonDict)
        return currentUserDict
    
def GetAncestry(currentUserDict):
    """Gets a 4 generation pedigree of the currently logged in user from FamilySearch

    Parameters
        currentUserDict: a dictionary that contains data about the current user
    Return: a dictionary with the 4 generation pedigree of the current user
    """
    global tokenDict

    if (devEnvironment == "Production"):
        regularBaseUri = regProduction
    elif (devEnvironment == "Beta"):
        regularBaseUri = regBeta
    elif (devEnvironment == "Integration"):
        regularBaseUri = regIntegration

    apiRoute = "platform/tree/ancestry"
    person = "?person=" + currentUserDict.users[0].personId
    generations = "&generations=4"
    apiRequest = f"{regularBaseUri}{apiRoute}{person}{generations}"

    headers = {
        "Accept": "application/json",
        "Authorization": "Bearer " + tokenDict.access_token
    }

    response = requests.get(apiRequest, headers=headers)

    if (response.status_code == 200):
        jsonDict = json.loads(response.text)
        pedigreeDict = Dict(jsonDict)
        return pedigreeDict
    
def CreatePersonsList(pedigreeDict):
    """Creates a list of persons with gender from FamilySearch

    Parameters
        pedigreeDict: a dictionary containing the pedigree of the current user
    Return: a list of people generated from the pedigree of the current user
    """
    persons = []

    for i in range(len(pedigreeDict.persons)):
        person = pedigreeDict.persons[i].display.name
        pID = pedigreeDict.persons[i].id
        print(f"{person} : {pID}")

def BeginFamilySearchAuth():
    """Starts the FamilySearch authentication flow, and prints ancestry list of 4 generations
    for current user.
    """
    outState = str(random.randint(2000000, 3000000))

    codeVerifier, codeChallenge = pkce.generate_pkce_pair()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    serverName = "127.0.0.1"
    serverAddress = (serverName, 5000)
    sock.bind(serverAddress)
    sock.listen(1)

    if (devEnvironment == "Production"):
        authBaseUri = authProduction
    elif (devEnvironment == "Beta"):
        authBaseUri = authBeta
    elif (devEnvironment == "Integration"):
        authBaseUri = authIntegration

    authRequest = f"{authBaseUri}?client_id={clientID}&redirect_uri={redirectUri}&response_type=code&state={outState}&code_challenge={codeChallenge}&code_challenge_method=S256&scope=openid%20profile%20email%20qualifies_for_affiliate_account%20country"

    webbrowser.open(authRequest)

    while True:
        connection, clientAddress = sock.accept()
        data = connection.recv(1000)
        connection.send(b'HTTP/1.0 200 OK\n')
        connection.send(b'Content-Type: text/html\n')
        connection.send(b'\n')
        connection.send(b"""
        <html>
        <script>window.close();
        </script>
        <body>
        </body>
        </html>
        """)
        connection.close()
        break

    data = str(data)
    data = data.split("?")
    data = data[1]
    data = data.split(" ")
    data = data[0]
    data = data.split("&")
    authCode = data[0]
    inState = data[1]

    authCode = CodeToSplit(data[0])
    inState = CodeToSplit(data[1])

    if inState == outState:
        GetAccessToken(authCode, codeVerifier)
        DecodeJWT()
        currentUserDict = GetCurrentUser()
        pedigreeDict = GetAncestry(currentUserDict)
        CreatePersonsList(pedigreeDict)

def Main():
    BeginFamilySearchAuth()

if __name__ == "__main__":
    Main()