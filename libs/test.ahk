#Include Socket.ahk

A := new ClientSocketTLS("balls")

A.Connect(["172.31.73.101", 8080])

A.StartTLS()
Sleep, 1000


T := "Hello world!"

A.Send(&T, StrPut(T))