#Include Socket.ahk

A := new ClientSocketTLS("ball")

A.Connect(["172.20.126.15", 8080])

A.StartTLS()
Sleep, 1000


T := "Hello world!"

SendSize := StrPut(T, "UTF-8")
VarSetCapacity(SendBuffer, SendSize, 0)
StrPut(T, &SendBuffer, "UTF-8")

A.Send(&SendBuffer, SendSize)