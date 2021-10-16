#Include Socket.ahk

A := new ClientSocketTLS("ball")

A.Connect(["172.29.14.24", 8080])

A.OnRecv := Func("Recv")

;A.StartTLS()
Sleep, 1000


T := "GET / HTTP/1.1`r`n`r`n"

SendSize := StrPut(T, "UTF-8")
VarSetCapacity(SendBuffer, SendSize, 0)
StrPut(T, &SendBuffer, "UTF-8")

A.Send(&SendBuffer, SendSize)

Sleep, 1000

A.Disconnect()

Recv(Sock) {
    Size := Sock.MsgSize()
    VarSetCapacity(Data, Size)

    Sock.Recv(Data, Size)

    s := StrGet(&Data, "UTF-8")

    MsgBox, % s
}