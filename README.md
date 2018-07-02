The default local port number for both client and server is 3780

1. Start client:
java -jar ActivityStreamerClient.jar -rp <serverPortNumber> -rh <anyServerName> -lp <localPortNumber> -u <userName> -s <secret>

  Example:
    java -jar ActivityStreamerClient.jar -rp 3780 -rh localhost -lp 3500 -u "test" -s "asdfasdn"
  Explaination:
    - when no -u or -s params, login as anonymous
    - when has -u but no -s params, register the user with user name and the client will generate the secret for user
    - when has -u and -s params, login with userName and secret

2. Start server:
java -jar ActivityStreamerServer.jar -rp <anyPortNumber> -rh <anyServerName> -lp <localPortNumber>

  Example:
- Run first: java -jar ActivityStreamerServer.jar
- Run next: java -jar ActivityStreamerServer.jar -rp 3780 -rh localhost -lp 3781
    Explaination:
    - when no param, server starts as the first server and does not connect to the others
    - when has -rp and -rh, server starts as the server connecting to the remote server
    - when has all params, server starts as the server connecting to the remote server with specific port number
