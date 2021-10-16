class Socket
{
	static WM_SOCKET := 0x9987, MSG_PEEK := 2
	static FD_READ := 1, FD_ACCEPT := 8, FD_CLOSE := 32
	static Blocking := True, BlockSleep := 50
	
	__New(Socket:=-1)
	{
		static Init
		if (!Init)
		{
			DllCall("LoadLibrary", "Str", "Ws2_32", "Ptr")
			VarSetCapacity(WSAData, 394+A_PtrSize)
			if (Error := DllCall("Ws2_32\WSAStartup", "UShort", 0x0202, "Ptr", &WSAData))
				throw Exception("Error starting Winsock",, Error)
			if (NumGet(WSAData, 2, "UShort") != 0x0202)
				throw Exception("Winsock version 2.2 not available")
			Init := True
		}
		this.Socket := Socket
	}
	
	__Delete()
	{
		if (this.Socket != -1)
			this.Disconnect()
	}
	
	Connect(Address)
	{
		if (this.Socket != -1)
			throw Exception("Socket already connected")
		Next := pAddrInfo := this.GetAddrInfo(Address)
		while Next
		{
			ai_addrlen := NumGet(Next+0, 16, "UPtr")
			ai_addr := NumGet(Next+0, 16+(2*A_PtrSize), "Ptr")
			if ((this.Socket := DllCall("Ws2_32\socket", "Int", NumGet(Next+0, 4, "Int")
				, "Int", this.SocketType, "Int", this.ProtocolId, "UInt")) != -1)
			{
				if (DllCall("Ws2_32\WSAConnect", "UInt", this.Socket, "Ptr", ai_addr
					, "UInt", ai_addrlen, "Ptr", 0, "Ptr", 0, "Ptr", 0, "Ptr", 0, "Int") == 0)
				{
					DllCall("Ws2_32\freeaddrinfo", "Ptr", pAddrInfo) ; TODO: Error Handling
					return this.EventProcRegister(this.FD_READ | this.FD_CLOSE)
				}
				this.Disconnect()
			}
			Next := NumGet(Next+0, 16+(3*A_PtrSize), "Ptr")
		}
		throw Exception("Error connecting")
	}
	
	Bind(Address)
	{
		if (this.Socket != -1)
			throw Exception("Socket already connected")
		Next := pAddrInfo := this.GetAddrInfo(Address)
		while Next
		{
			ai_addrlen := NumGet(Next+0, 16, "UPtr")
			ai_addr := NumGet(Next+0, 16+(2*A_PtrSize), "Ptr")
			if ((this.Socket := DllCall("Ws2_32\socket", "Int", NumGet(Next+0, 4, "Int")
				, "Int", this.SocketType, "Int", this.ProtocolId, "UInt")) != -1)
			{
				if (DllCall("Ws2_32\bind", "UInt", this.Socket, "Ptr", ai_addr
					, "UInt", ai_addrlen, "Int") == 0)
				{
					DllCall("Ws2_32\freeaddrinfo", "Ptr", pAddrInfo) ; TODO: ERROR HANDLING
					return this.EventProcRegister(this.FD_READ | this.FD_ACCEPT | this.FD_CLOSE)
				}
				this.Disconnect()
			}
			Next := NumGet(Next+0, 16+(3*A_PtrSize), "Ptr")
		}
		throw Exception("Error binding")
	}
	
	Listen(backlog=32)
	{
		return DllCall("Ws2_32\listen", "UInt", this.Socket, "Int", backlog) == 0
	}
	
	Accept()
	{
		if ((s := DllCall("Ws2_32\accept", "UInt", this.Socket, "Ptr", 0, "Ptr", 0, "Ptr")) == -1)
			throw Exception("Error calling accept",, this.GetLastError())
		Sock := new Socket(s)
		Sock.ProtocolId := this.ProtocolId
		Sock.SocketType := this.SocketType
		Sock.EventProcRegister(this.FD_READ | this.FD_CLOSE)
		return Sock
	}
	
	Disconnect()
	{
		; Return 0 if not connected
		if (this.Socket == -1)
			return 0
		
		; Unregister the socket event handler and close the socket
		this.EventProcUnregister()
		if (DllCall("Ws2_32\closesocket", "UInt", this.Socket, "Int") == -1)
			throw Exception("Error closing socket",, this.GetLastError())
		this.Socket := -1
		return 1
	}
	
	MsgSize()
	{
		static FIONREAD := 0x4004667F
		if (DllCall("Ws2_32\ioctlsocket", "UInt", this.Socket, "UInt", FIONREAD, "UInt*", argp) == -1)
			throw Exception("Error calling ioctlsocket",, this.GetLastError())
		return argp
	}
	
	Send(pBuffer, BufSize, Flags:=0)
	{
		if ((r := DllCall("Ws2_32\send", "UInt", this.Socket, "Ptr", pBuffer, "Int", BufSize, "Int", Flags)) == -1)
			throw Exception("Error calling send",, this.GetLastError())
		return r
	}
	
	SendText(Text, Flags:=0, Encoding:="UTF-8")
	{
		local

		VarSetCapacity(Buffer, StrPut(Text, Encoding) * ((Encoding="UTF-16"||Encoding="cp1200") ? 2 : 1))
		Length := StrPut(Text, &Buffer, Encoding)
		return this.Send(&Buffer, Length - 1)
	}
	
	Recv(ByRef Buffer, BufSize:=0, Flags:=0)
	{
		local

		while (!(Length := this.MsgSize()) && this.Blocking)
			Sleep, this.BlockSleep
		if !Length
			return 0
		if !BufSize
			BufSize := Length
		VarSetCapacity(Buffer, BufSize)
		if ((r := DllCall("Ws2_32\recv", "UInt", this.Socket, "Ptr", &Buffer, "Int", BufSize, "Int", Flags)) == -1)
			throw Exception("Error calling recv",, this.GetLastError())
		return r
	}
	
	RecvText(BufSize:=0, Flags:=0, Encoding:="UTF-8")
	{
		local

		if (Length := this.Recv(Buffer, BufSize, flags))
			return StrGet(&Buffer, Length, Encoding)
		return ""
	}
	
	RecvLine(BufSize:=0, Flags:=0, Encoding:="UTF-8", KeepEnd:=False)
	{
		while !(i := InStr(this.RecvText(BufSize, Flags|this.MSG_PEEK, Encoding), "`n"))
		{
			if !this.Blocking
				return ""
			Sleep, this.BlockSleep
		}
		if KeepEnd
			return this.RecvText(i, Flags, Encoding)
		else
			return RTrim(this.RecvText(i, Flags, Encoding), "`r`n")
	}
	
	GetAddrInfo(Address)
	{
		; TODO: Use GetAddrInfoW
		Host := Address[1], Port := Address[2]
		VarSetCapacity(Hints, 16+(4*A_PtrSize), 0)
		NumPut(this.SocketType, Hints, 8, "Int")
		NumPut(this.ProtocolId, Hints, 12, "Int")
		if (Error := DllCall("Ws2_32\getaddrinfo", "AStr", Host, "AStr", Port, "Ptr", &Hints, "Ptr*", Result))
			throw Exception("Error calling GetAddrInfo",, Error)
		return Result
	}
	
	OnMessage(wParam, lParam, Msg, hWnd)
	{
		Critical
		if (Msg != this.WM_SOCKET || wParam != this.Socket)
			return
		if (lParam & this.FD_READ)
			this.onRecv()
		else if (lParam & this.FD_ACCEPT)
			this.onAccept()
		else if (lParam & this.FD_CLOSE)
			this.EventProcUnregister(), this.OnDisconnect()
	}
	
	EventProcRegister(lEvent)
	{
		this.AsyncSelect(lEvent)
		if !this.Bound
		{
			this.Bound := this.OnMessage.Bind(this)
			OnMessage(this.WM_SOCKET, this.Bound)
		}
	}
	
	EventProcUnregister()
	{
		this.AsyncSelect(0)
		if this.Bound
		{
			OnMessage(this.WM_SOCKET, this.Bound, 0)
			this.Bound := False
		}
	}
	
	AsyncSelect(lEvent)
	{
		if (DllCall("Ws2_32\WSAAsyncSelect"
			, "UInt", this.Socket    ; s
			, "Ptr", A_ScriptHwnd    ; hWnd
			, "UInt", this.WM_SOCKET ; wMsg
			, "UInt", lEvent) == -1) ; lEvent
			throw Exception("Error calling WSAAsyncSelect",, this.GetLastError())
	}
	
	GetLastError()
	{
		return DllCall("Ws2_32\WSAGetLastError")
	}
}

class SocketTCP extends Socket
{
	static ProtocolId := 6 ; IPPROTO_TCP
	static SocketType := 1 ; SOCK_STREAM
}

class SocketUDP extends Socket
{
	static ProtocolId := 17 ; IPPROTO_UDP
	static SocketType := 2  ; SOCK_DGRAM
	
	SetBroadcast(Enable)
	{
		static SOL_SOCKET := 0xFFFF, SO_BROADCAST := 0x20
		if (DllCall("Ws2_32\setsockopt"
			, "UInt", this.Socket ; SOCKET s
			, "Int", SOL_SOCKET   ; int    level
			, "Int", SO_BROADCAST ; int    optname
			, "UInt*", !!Enable   ; *char  optval
			, "Int", 4) == -1)    ; int    optlen
			throw Exception("Error calling setsockopt",, this.GetLastError())
	}
}

MoveMemory(pTo, pFrom, Size) {
	DllCall("RtlMoveMemory", "Ptr", pTo, "Ptr", pFrom, "UInt", Size)
}


class ClientSocketTLS extends SocketTCP {
	BlockingRecv(pBuffer, Size, Flags = 0) {
		VarSetCapacity(ReadSet, A_PtrSize + (64 * A_PtrSize), 0)

		NumPut(1          , ReadSet, 0        , "UInt")
		NumPut(this.Socket, ReadSet, A_PtrSize, "Ptr")

		if ((r := DllCall("Ws2_32\select", "UInt", 0, "Ptr", &ReadSet, "Ptr", 0, "Ptr", 0, "Ptr", 0, "Int")) == -1)
			throw Exception("Error calling select",, this.GetLastError())

		if ((r := DllCall("Ws2_32\recv", "UInt", this.Socket, "Ptr", pBuffer, "Int", Size, "Int", Flags)) == -1)
			throw Exception("Error calling recv",, this.GetLastError())
		return r
	}

	__New(Hostname) {
		this.Hostname := Hostname

		SocketTCP.__New.Call(this)

		this.RawSend := SocketTCP.Send
	}

	static NOT_TLS := 0
	static WAIT_FOR_SERVER_HELLO := 1
	static TLS := 2

	State := ClientSocketTLS.NOT_TLS

	static SEC_E_OK := 0

	CreateCred() {
		static SCHANNEL_CRED_VERSION := 4
		static SR_PROT_TLS1_2_CLIENT := 0x00000800

		static SCH_CRED_NO_DEFAULT_CREDS := 0x00000010
		static SCH_CRED_MANUAL_CRED_VALIDATION  := 0x00000008
		static SCH_USE_STRONG_CRYPTO := 0x00400000

		static Flags := SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_MANUAL_CRED_VALIDATION  | SCH_USE_STRONG_CRYPTO

		VarSetCapacity(SCHANNEL_CRED, A_PtrSize == 8 ? 80 : 56, 0)

		NumPut(SCHANNEL_CRED_VERSION, SCHANNEL_CRED, 0, "UInt")
		NumPut(SR_PROT_TLS1_2_CLIENT, SCHANNEL_CRED, A_PtrSize == 8 ? 56 : 32, "UInt")
		NumPut(Flags                , SCHANNEL_CRED, A_PtrSize == 8 ? 72 : 48, "UInt")

		static SECPKG_CRED_OUTBOUND := 0x2

		this.SetCapacity("CredHandle", A_PtrSize * 2)
		this.SetCapacity("TimeStamp", A_PtrSize)

		Status := DllCall("Secur32.dll\AcquireCredentialsHandle"
			, "Ptr", 0
			, "Str", "Microsoft Unified Security Protocol Provider"
			, "UInt", SECPKG_CRED_OUTBOUND
			, "Ptr", 0
			, "Ptr", &SCHANNEL_CRED
			, "Ptr", 0
			, "Ptr", 0
			, "Ptr", this.GetAddress("CredHandle")
			, "Ptr", this.GetAddress("TimeStamp"))

		if (Status != this.SEC_E_OK) {
			Throw Exception("AcquireCredentialsHandle failed, error code " Format("{:x}", Status & 0xFFFFFFFF))
		}
	}
	
	static SEC_I_CONTINUE_NEEDED := 0x00090312

	static ISC_REQ_ALLOCATE_MEMORY        := 0x00000100
	static ISC_REQ_CONFIDENTIALITY        := 0x00000010
	static ISC_REQ_EXTENDED_ERROR         := 0x00004000
	static ISC_REQ_REPLAY_DETECT          := 0x00004000
	static ISC_REQ_SEQUENCE_DETECT        := 0x00000008
	static ISC_REQ_STREAM                 := 0x00008000
	static ISC_REQ_MANUAL_CRED_VALIDATION := 0x00080000

	static Flags := ClientSocketTLS.ISC_REQ_ALLOCATE_MEMORY | ClientSocketTLS.ISC_REQ_CONFIDENTIALITY
		| ClientSocketTLS.ISC_REQ_EXTENDED_ERROR | ClientSocketTLS.ISC_REQ_REPLAY_DETECT
		| ClientSocketTLS.ISC_REQ_SEQUENCE_DETECT | ClientSocketTLS.ISC_REQ_STREAM 
		| ClientSocketTLS.ISC_REQ_MANUAL_CRED_VALIDATION

	ClientHello() {
		static SECBUFFER_VERSION := 0
		static SECBUFFER_TOKEN := 2

		this.SetCapacity("ContextHandle", A_PtrSize * 2)

		VarSetCapacity(SecBufferDescription, 8 + A_PtrSize, 0)
		VarSetCapacity(SecBuffer, 8 + A_PtrSize, 0)

		NumPut(SECBUFFER_TOKEN, SecBuffer, 4, "UInt") ; SecBuffer.Type = SECBUFFER_TOKEN

		NumPut(SECBUFFER_VERSION, SecBufferDescription, 0, "UInt") ; SecBufferDesc.Version = SECBUFFER_VERSION
		NumPut(1                , SecBufferDescription, 4, "UInt") ; SecBufferDesc.Count = 1
		NumPut(&SecBuffer       , SecBufferDescription, 8, "Ptr")  ; SecBufferDesc.Data = &SecBuffer

		Status := DllCall("Secur32.dll\InitializeSecurityContext"
			, "Ptr", this.GetAddress("CredHandle")
			, "Ptr", 0
			, "Str", this.HostName
			, "UInt", this.Flags
			, "Ptr", 0
			, "Ptr", 0
			, "Ptr", 0
			, "Ptr", 0
			, "Ptr", this.GetAddress("ContextHandle")
			, "Ptr", &SecBufferDescription
			, "UInt*", OutFlags
			, "Ptr", this.GetAddress("TimeStamp"))
		
		this.Flags := OutFlags

		if (Status != this.SEC_I_CONTINUE_NEEDED) {
			Throw Exception("ClientHello InitializeSecurityContext failed, error code " Format("{:x}", Status & 0xFFFFFFFF))
		}

		Size := NumGet(SecBuffer, 0, "UInt")
		pData := NumGet(SecBuffer, 8, "Ptr")

		this.RawSend(pData, Size)

		DllCall("Secur32.dll\FreeContextBuffer", "Ptr", pData)

		this.State := ClientSocketTLS.WAIT_FOR_SERVER_HELLO
	}

	static SEC_E_INCOMPLETE_MESSAGE := 0x80090318

	HandshakeLoop() {
		static SECBUFFER_VERSION := 0
		static SECBUFFER_EMPTY := 0
		static SECBUFFER_TOKEN := 2
		static SECBUFFER_EXTRA := 5

		HandshakeBufferSize := 2 ** 16 - 1
		VarSetCapacity(HandshakeBuffer, HandshakeBufferSize)
		HandshakeBufferIndex := 0

		Status := this.SEC_I_CONTINUE_NEEDED

		while (Status = this.SEC_I_CONTINUE_NEEDED || Status = this.SEC_E_INCOMPLETE_MESSAGE) {
			if (HandshakeBufferIndex = 0 || Status = this.SEC_E_INCOMPLETE_MESSAGE) {
				HandshakeBufferIndex += this.BlockingRecv(&HandshakeBuffer + HandshakeBufferIndex, HandshakeBufferSize - HandshakeBufferIndex)
			}

			static SIZEOF_SECBUFFERDESC := 8 + A_PtrSize
			static SIZEOF_SECBUFFER     := 8 + A_PtrSize

			; Input buffers

			VarSetCapacity(InBuffers, SIZEOF_SECBUFFER * 2)

			NumPut(HandshakeBufferIndex, InBuffers, 0, "UInt") ; SecBuffer.Size = 
			NumPut(SECBUFFER_TOKEN     , InBuffers, 4, "UInt") ; SecBuffer.Type = 
			NumPut(&HandshakeBuffer    , InBuffers, 8, "Ptr")  ; SecBuffer.Ptr = 

			NumPut(0              , InBuffers, SIZEOF_SECBUFFER + 0, "UInt") ; SecBuffer.Size = 
			NumPut(SECBUFFER_EMPTY, InBuffers, SIZEOF_SECBUFFER + 4, "UInt") ; SecBuffer.Type = 
			NumPut(0              , InBuffers, SIZEOF_SECBUFFER + 8, "Ptr")  ; SecBuffer.Ptr = 

			VarSetCapacity(InDesc, SIZEOF_SECBUFFERDESC)

			NumPut(SECBUFFER_VERSION, InDesc, 0, "UInt") ; SecBufferDesc.Version =
			NumPut(2                , InDesc, 4, "UInt") ; SecBufferDesc.Count =
			NumPut(&InBuffers       , InDesc, 8, "Ptr")  ; SecBufferDesc.Data =

			; Output buffer

			VarSetCapacity(OutBuffer, SIZEOF_SECBUFFER)

			NumPut(0              , OutBuffer, 0, "UInt") ; SecBuffer.Size = 
			NumPut(SECBUFFER_TOKEN, OutBuffer, 4, "UInt") ; SecBuffer.Type = 
			NumPut(0              , OutBuffer, 8, "Ptr")  ; SecBuffer.Ptr = 

			VarSetCapacity(OutDesc, SIZEOF_SECBUFFERDESC)

			NumPut(SECBUFFER_VERSION, OutDesc, 0, "UInt") ; SecBufferDesc.Version =
			NumPut(1                , OutDesc, 4, "UInt") ; SecBufferDesc.Count =
			NumPut(&OutBuffer       , OutDesc, 8, "Ptr")  ; SecBufferDesc.Data =


			Status := DllCall("Secur32.dll\InitializeSecurityContext"
				, "Ptr", this.GetAddress("CredHandle")
				, "Ptr", this.GetAddress("ContextHandle")
				, "Ptr", 0
				, "UInt", this.Flags
				, "Ptr", 0
				, "Ptr", 0
				, "Ptr", &InDesc
				, "Ptr", 0
				, "Ptr", 0
				, "Ptr", &OutDesc
				, "UInt*", OutFlags
				, "Ptr", this.GetAddress("TimeStamp")
				, "UInt")

			if (Status = this.SEC_E_OK || Status = this.SEC_I_CONTINUE_NEEDED) {
				if ((OutSize := NumGet(OutBuffer, 0, "UInt")) != 0 && (pOutData := NumGet(OutBuffer, 8, "Ptr")) != 0) {
					this.RawSend(pOutData, OutSize)

					DllCall("Secur32.dll\FreeContextBuffer", "Ptr", pOutData)
				}
			}

			if (Status = this.SEC_E_INCOMPLETE_MESSAGE) {
				continue
			}

			HasExtraData := NumGet(&InBuffers + SIZEOF_SECBUFFER, 4, "UInt") = SECBUFFER_EXTRA
			
			if (Status = this.SEC_E_OK) {
				if (HasExtraData) {
					; TODO: handle
				}

				break
			}
			else if (Status & 0x80000000) {
				Throw Exception("ServerHello InitializeSecurityContext failed, error code " Format("{:x}", Status & 0xFFFFFFFF))
			}
			
			if (HasExtraData) {
				ExtraDataSize := NumGet(&InBuffers + SIZEOF_SECBUFFER, 0, "UInt")

				MoveMemory(&HandshakeBuffer, &HandshakeBuffer + (HandshakeBufferIndex - ExtraDataSize), ExtraDataSize)
			}
			else {
				HandshakeBufferIndex := 0
			}
		}

		static SECPKG_ATTR_STREAM_SIZES := 4

		VarSetCapacity(StreamSizes, 20, 0)
		
		Status := DllCall("Secur32.dll\QueryContextAttributes"
			, "Ptr", this.GetAddress("ContextHandle")
			, "UInt", SECPKG_ATTR_STREAM_SIZES
			, "Ptr", &StreamSizes)

		if (Status != ClientSocketTLS.SEC_E_OK) {
			Throw Exception("ServerHello QueryContextAttributes failed, error code " Format("{:x}", Status & 0xFFFFFFFF))
		}

		this.HeaderSize         := NumGet(StreamSizes, 0, "UInt")
		this.TrailerSize        := NumGet(StreamSizes, 4, "UInt")
		this.MaximumMessageSize := NumGet(StreamSizes, 8, "UInt")
		this.BufferCount        := NumGet(StreamSizes, 12, "UInt")
		this.BlockSize          := NumGet(StreamSizes, 16, "UInt")

		this.MaxPayloadSize := this.MaximumMessageSize - this.HeaderSize - this.TrailerSize

		this.State := ClientSocketTLS.TLS
	}

	StartTLS() {
		this.CreateCred()
		this.ClientHello()

		this.HandshakeLoop()
	}

	Send(pBuffer, Size) {
		if (this.State != ClientSocketTLS.TLS) {
			Throw Exception("The TLS handshake has not been completed, and data cannot be safely sent over the socket")
		}

		VarSetCapacity(MessageBuffer, this.HeaderSize + Size + this.TrailerSize, 0)

		MoveMemory(&MessageBuffer + this.HeaderSize, pBuffer, Size)

		static SIZEOF_SECBUFFERDESC := 8 + A_PtrSize
		static SIZEOF_SECBUFFER     := 8 + A_PtrSize

		VarSetCapacity(OutDesc, SIZEOF_SECBUFFERDESC, 0)
		VarSetCapacity(OutBuffers, SIZEOF_SECBUFFER * 4, 0)

		static SECBUFFER_EMPTY := 0
		static SECBUFFER_DATA := 1
		static SECBUFFER_STREAM_TRAILER := 6
		static SECBUFFER_STREAM_HEADER := 7

		NumPut(this.HeaderSize        , OutBuffers, 0, "UInt") ; SecBuffer.Size = 
		NumPut(SECBUFFER_STREAM_HEADER, OutBuffers, 4, "UInt") ; SecBuffer.Type = 
		NumPut(&MessageBuffer         , OutBuffers, 8, "Ptr")  ; SecBuffer.Ptr = 

		NumPut(Size                            , OutBuffers, SIZEOF_SECBUFFER + 0, "UInt") ; SecBuffer.Size = 
		NumPut(SECBUFFER_DATA                  , OutBuffers, SIZEOF_SECBUFFER + 4, "UInt") ; SecBuffer.Type = 
		NumPut(&MessageBuffer + this.HeaderSize, OutBuffers, SIZEOF_SECBUFFER + 8, "Ptr")  ; SecBuffer.Ptr = 

		NumPut(this.TrailerSize                       , OutBuffers, (SIZEOF_SECBUFFER * 2) + 0, "UInt") ; SecBuffer.Size = 
		NumPut(SECBUFFER_STREAM_TRAILER               , OutBuffers, (SIZEOF_SECBUFFER * 2) + 4, "UInt") ; SecBuffer.Type = 
		NumPut(&MessageBuffer + this.HeaderSize + Size, OutBuffers, (SIZEOF_SECBUFFER * 2) + 8, "Ptr")  ; SecBuffer.Ptr = 

		NumPut(0              , OutBuffers, (SIZEOF_SECBUFFER * 3) + 0, "UInt") ; SecBuffer.Size = 
		NumPut(SECBUFFER_EMPTY, OutBuffers, (SIZEOF_SECBUFFER * 3) + 4, "UInt") ; SecBuffer.Type = 
		NumPut(0              , OutBuffers, (SIZEOF_SECBUFFER * 3) + 8, "Ptr")  ; SecBuffer.Ptr = 

		NumPut(SECBUFFER_VERSION, OutDesc, 0, "UInt") ; SecBufferDesc.Version =
		NumPut(4                , OutDesc, 4, "UInt") ; SecBufferDesc.Count =
		NumPut(&OutBuffers      , OutDesc, 8, "Ptr")  ; SecBufferDesc.Data =

		Status := DllCall("Secur32.dll\EncryptMessage"
			, "Ptr", this.GetAddress("ContextHandle")
			, "Ptr", 0
			, "Ptr", &OutDesc
			, "Ptr", 0
			, "UInt")
		
		this.RawSend(&MessageBuffer, this.HeaderSize + Size + this.TrailerSize)
	}
}