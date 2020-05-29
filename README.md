# Trapdoor

Trapdoor allows you to connect to TTY applications from a web browser through
WebSocket.

## Development

Trapdoor uses Azure AD as an identity provider and restricts access to
applications based on the roles a user is assigned to. You'll need to set up an
app registration and app roles in Azure AD, and set up the environment
variables:

    $ cat .env
    TRAPDOOR_OAUTH2_CLIENT_ID=<Client ID>
    TRAPDOOR_OAUTH2_CLIENT_SECRET=<Client secret>
    TRAPDOOR_AZURE_TENANT_ID=<Tenant ID>

Then start containers:

    $ docker-compose up -d

The console will be available at http://localhost:3000.

### Building binary

    make

### Building Docker image

    docker build .
