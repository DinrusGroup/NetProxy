#include "NetProxy.h"

namespace Upp {

const char* NetProxy::GetMsg(int code)
{
	static const Tuple<int, const char*> errors[] = {
		// NetProxy error messages.
		{ 10000,	t_("Отсутствует обслуживаемый клиент (не прикреплён сокет).") },
		{ 10001,	t_("Не указан адрес или порт прокси.") },
		{ 10002,	t_("Целевой адрес или порт не указан.") },
		{ 10003,	t_("Не удалось разрешить адрес.") },
		{ 10004,	t_("Не удалось подключиться к прокси-серверу.") },
		{ 10005,	t_("Неудачный старт переговорного процесса по SSL-протоколу.") },
		{ 10006,	t_("Получен повреждённый пакет.") },
		{ 10007,	t_("Имелась ошибка сокета.") },
		{ 10008,	t_("Операция была прервана.") },
		{ 10009,	t_("Вышло максимальное время на подключения (таймаут).") },
		// Http CONNECT method error messages.
		{ 10010,	t_("Метод Http CONNECT завершился неудачно.") },
		{ 10011,	t_("Истользовать BIND при туннелировании Http невозможно. Попробуйте подключение по протоколу Socks.") },
		// SOCKS4 protocol error messages.
		{ 91,		t_("Запрос отвергнут или не удался.") },
		{ 92,		t_("Запрос не удался. На клиенте не запущен identd (или он недоступен с этого сервера).") },
		{ 93,		t_("Запрос не удался. identd на клиенте не смог подтвердить идентификатор пользователя, указанный в запросе.") },
		{ 94,		t_("Протокол Socks4 не поддерживает семейство адресов IP версииn 6. Попробуйте вместо него протокол Socks5.") },
		// SOCKS5 protocol error messages.
		{ 1,		t_("Общая неудача.") },
		{ 2,		t_("Набор правил запрещает подключение.")},
		{ 3,		t_("Сеть вне доступа.") },
		{ 4,		t_("Целевая машина вне доступа.") },
		{ 5,		t_("Целевой хост отверг подключение.")},
		{ 6,		t_("Истёк срок TTL.") },
		{ 7,		t_("Команда не поддерживается / ошибка протокола.") },
		{ 8,		t_("Тип адреса не поддерживается.") },
		{ 255,		t_("Неверный метод аутентификации. Приемлемых методов не предложено.") },
		{ 256,		t_("Провал аутентификации.") },
	};
	const Tuple<int, const char *> *x = FindTuple(errors, __countof(errors), code);
	return x ? x->b : "-1";
}

static bool sTrace = false;
static bool sTraceVerbose = false;

#define LLOG(x)       do { if(sTrace) RLOG("NetProxy: " << x); } while(false)
#define LDUMPHEX(x)	  do { if(sTraceVerbose) RDUMPHEX(x); } while(false)

static  bool NtoP(int family, const String& in, String& bound_ip)
{
	// MingWG has some issues with InetNtop or inet_ntop functions on windows...

	if(family == AF_INET && in.GetLength() != 4 ||
		family == AF_INET6 && in.GetLength() != 16)
			return false;

	const uint8 *p = (uint8*) in.Begin();
	if(family == AF_INET) {
		bound_ip = Format("%d.%d.%d.%d", *p, *(p + 1), *(p + 2), *(p + 3));
	}
	else
	if(family == AF_INET6) {
		bound_ip = Format("%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
		                  "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
			*p, *(p + 1), *(p + 2), *(p + 3), *(p + 4), *(p + 5),
			*(p + 6), *(p + 7), *(p + 8), *(p + 9), *(p + 10),
			*(p + 11), *(p + 12), *(p + 13), *(p + 14),*(p + 15));
	}
	LDUMPHEX(bound_ip);
	return true;
}

void NetProxy::Trace(bool b)
{
	sTrace = b;
	sTraceVerbose = false;
}

void NetProxy::TraceVerbose(bool b)
{
	NetProxy::Trace(b);
	sTraceVerbose = b;
}

bool NetProxy::Init()
{
	LLOG("Запуск... ");
	if(!socket)
		SetError(NO_SOCKET_ATTACHED);

	if(proxy_host.IsEmpty() || !proxy_port)
		SetError(HOST_NOT_SPECIFIED);

	if(target_host.IsEmpty() || !target_port)
		SetError(TARGET_NOT_SPECIFIED);

	timeout_backup = socket->GetTimeout();
	socket->GlobalTimeout(timeout);
	socket->Timeout(0);
	packet.Clear();
	packet_length = 0;
	bound = false;
	status = WORKING;
	start_time = msecs();
	ipinfo.Start(proxy_host, proxy_port);
	events = WAIT_READ | WAIT_WRITE;
	LLOG(Format("Подключение к прокси-серверу: %s:%d", proxy_host, proxy_port));
	return true;
}

bool NetProxy::Exit()
{
	if(socket) {
		socket->Timeout(timeout_backup);
		socket = nullptr;
		events  = 0;
		LLOG("Выход...");
	}
	return true;
}

bool NetProxy::Dns()
{
	auto b = !ipinfo.InProgress();
	if(b) {
		if(!ipinfo.GetResult())
			SetError(DNS_FAILED);
	}
	return b;
}

bool NetProxy::Connect()
{
	auto b = socket->Connect(ipinfo);
	if(b) {
		ipinfo.Clear();
		LLOG(Format("Успешно подключился к прокси-серверу по адресу %s:%d",
			proxy_host, proxy_port));
	}
	return b;
}

bool NetProxy::Get()
{
	while(!IsTimeout()) {
		char c;
		if(socket->Get(&c, sizeof(char)) == 0)
			break;
		packet.Cat(c);
		if(IsEof()) {
			return true;
		}
	}
	return false;
}

bool NetProxy::Put()
{
	while(!IsTimeout()) {
		int n = packet.GetLength() - packet_length;
		n = socket->Put(~packet + packet_length, n);
		if(n == 0)
			break;
		packet_length += n;
		if(packet_length == packet.GetLength()) {
			packet.Clear();
			packet_length = 0;
			return true;
		}
	}
	return false;
}

void NetProxy::PutGet()
{
	queue.AddTail() = [=, this]{ return Put(); };
	queue.AddTail() = [=, this]{ return Get(); };
}

void NetProxy::StartSSL()
{
	queue.AddTail() = [=, this]{
		bool b = socket->StartSSL();
		if(b) LLOG("Успешно начались переговоры по SSL.");
		return b;
	};
	queue.AddTail() = [=, this]{
		bool b = socket->SSLHandshake();
		if(!b) LLOG("Успешное рукопожатие по SSL.");
		return !b;
	};
}

void NetProxy::Check()
{
	if(status != WORKING)
		return;
	if(IsTimeout())
		SetError(CONNECTION_TIMED_OUT);
	if(socket->IsError())
		throw Error("Ошибка сокета. " + socket->GetErrorDesc());
	if(socket->IsAbort())
		SetError(ABORTED);
}


void NetProxy::HttpcConnect()
{
	queue.Clear();
	{
		IsEof = [=, this] { return HttpcIsEof(); };
		queue.AddTail([=, this]{ return Init();});
		queue.AddTail([=, this]{ return Dns(); });
		queue.AddTail([=, this]{ return Connect();});
		queue.AddTail([=, this]{ return HttpcRequest(); });
	}
}

bool NetProxy::HttpcRequest()
{
	LLOG("Начало туннелирования HTTP_CONNECT...");
	packet.Clear();
	packet_length = 0;
	int port = Nvl(target_port, ssl ? 443 : 80);
	packet << "CONNECT " << target_host << ":" << port << " HTTP/1.1\r\n"
           << "Host: "   << target_host << ":" << port << "\r\n";
	if(!proxy_user.IsEmpty() && !proxy_password.IsEmpty())
		packet << "Proxy-Authorization: Basic " << Base64Encode(proxy_user + ":" + proxy_password) << "\r\n";
    packet << "\r\n";
	LLOG(">> HTTP_CONNECT: Отправка запроса.");
	LDUMPHEX(packet);
	PutGet();
	return true;
}

bool NetProxy::HttpcParseReply()
{
	LLOG("<< HTTP_CONNECT: Получен ответ на запрос.");
	LDUMPHEX(packet);
	int q = min(packet.Find('\r'), packet.Find('\n'));
	if(q >= 0)
		packet.Trim(q);
	if(!packet.StartsWith("HTTP") || packet.Find(" 2") < 0) {
		SetError(HTTPCONNECT_FAILED);
	}
	if(ssl) {
		StartSSL();
		return true;
	}
	LLOG("HTTP_CONNECT: Успешное подключение.");
	return Exit();
}

bool NetProxy::HttpcIsEof()
{
	if(packet.GetCount() > 3) {
		const char *c = packet.Last();
		if(c[-2] == '\n' && c[-1] == '\r' && c[0] == '\n') {
			return HttpcParseReply();
		}
	}
	return false;
}

bool NetProxy::SocksStart()
{
	LLOG(Format("Старт подключения по SOCKS%d.", proxy_type));
	packet_type = SOCKS5_HELO;
	if(!lookup) {
		ipinfo.Start(target_host, target_port);
		LLOG(Format("** SOCKS%d: Началось разрешение локального имени для %s:%d",
			proxy_type, target_host, target_port));
	}
	return true;
}

bool NetProxy::SocksCommand(int cmd)
{
	switch(cmd) {
		case BIND:
			if(!bound) {
				LLOG("SOCKS" << proxy_type << ":Получена инфо BIND.");
				bound = true;
				ParseBoundAddr();
				packet.Clear();
				packet_length = 0;
				queue.AddTail() = [=, this] { return Get(); };
				return true;
			}
			LLOG("SOCKS" << proxy_type << ": Команда BIND успешно выполнена.");
			break;
		case CONNECT:
			if(ssl) {
				StartSSL();
				LLOG("SOCKS" << proxy_type << ": Старт SSL...");
				return true;
			}
			LLOG(Format("SOCKS%d: Успешно подключен к %s:%d (через прокси %s:%d)",
				proxy_type, target_host, target_port, proxy_host, proxy_port));
			break;
		default:
			NEVER();
	}
	return Exit();
}

void NetProxy::Socks4Connect(int cmd)
{
	command = (byte) cmd;
	queue.Clear();
	{
		IsEof = [=, this] { return Socks4IsEof(); };
		queue.AddTail([=, this]{ return Init();});
		queue.AddTail([=, this]{ return Dns(); });
		queue.AddTail([=, this]{ return Connect();});
		queue.AddTail([=, this]{ return SocksStart(); });
		queue.AddTail([=, this]{ return !lookup ? Dns() : true; });
		queue.AddTail([=, this]{ return Socks4Request(); });
	}
}

bool NetProxy::Socks4Request()
{
	packet.Clear();
	packet_length = 0;
	{
		packet.Cat(0x04);
		packet.Cat(command);
		if(lookup) {
			uint16 port = htons(target_port);
			uint32 addr = htonl(0x00000001);
			packet.Cat((const char*) &port, sizeof(uint16));
			packet.Cat((const char*) &addr, sizeof(uint32));
		}
		else {
			auto *info = ipinfo.GetResult();
			if(info->ai_family == AF_INET6) {
				SetError(SOCKS4_ADDRESS_TYPE_NOT_SUPPORTED);
			}
			sockaddr_in *target = (sockaddr_in*) info->ai_addr;
			packet.Cat((const char*) &target->sin_port, sizeof(uint16));
			packet.Cat((const char*) &target->sin_addr.s_addr, sizeof(uint32));
			ipinfo.Clear();
		}
		if(!proxy_user.IsEmpty()) {
			packet.Cat(proxy_user);
		}
		packet.Cat(0x00);
		if(lookup) {
			packet.Cat(target_host);
			packet.Cat(0x00);
		}
	}
	LLOG(">> SOCKS4: Отправка запроса на подключение.");
	LDUMPHEX(packet);
	PutGet();
	return true;
}

bool NetProxy::Socks4ParseReply()
{
	LLOG("<< SOCKS4: Получен ответ на запрос.");
	LDUMPHEX(packet);
	auto *reply = (Reply::Socks4*) packet.Begin();
	if(reply->version != 0)
		SetError(INVALID_PACKET);
	if(reply->status != 0x5a)
		SetError(reply->status);
	return SocksCommand(command);
}

bool NetProxy::Socks4IsEof()
{
	bool   b = packet.GetCharCount() == sizeof(Reply::Socks4);
	if(b)  b = Socks4ParseReply();
	return b;
}

void NetProxy::Socks5Connect(int cmd)
{
	command = (byte) cmd;
	queue.Clear();
	{
		IsEof = [=, this] { return Socks5IsEof(); };
		queue.AddTail([=, this]{ return Init();});
		queue.AddTail([=, this]{ return Dns(); });
		queue.AddTail([=, this]{ return Connect();});
		queue.AddTail([=, this]{ return SocksStart(); });
		queue.AddTail([=, this]{ return !lookup ? Dns() : true; });
		queue.AddTail([=, this]{ return Socks5Request(); });
	}
}

bool NetProxy::Socks5Request()
{
	packet.Clear();
	packet_length = 0;

	if(packet_type == SOCKS5_HELO) {
		packet.Cat(0x05);
		packet.Cat(0x02);
		packet.Cat(0x00);
		packet.Cat(0x02);
		LLOG(">> SOCKS5: Отправка начальных приветствий.");
	}
	else
	if(packet_type == SOCKS5_AUTH) {
		packet.Cat(0x01);
		packet.Cat(proxy_user.GetLength());
		packet.Cat(proxy_user);
		packet.Cat(proxy_password.GetLength());
		packet.Cat(proxy_password);
		LLOG(">> SOCKS5: Отправка запроса на авторизацию.");
	}
	else
	if(packet_type == SOCKS5_REQUEST) {
		packet.Cat(0x05);
		packet.Cat(command);
		packet.Cat(0x00);
		if(lookup) {
			packet.Cat(0x03);
			packet.Cat(target_host.GetLength());
			packet.Cat(target_host);
			uint16 port = htons(target_port);
			packet.Cat((const char*) &port, sizeof(uint16));
		}
		else {
			struct addrinfo *info = ipinfo.GetResult();
			if(info->ai_family == AF_INET) {
				sockaddr_in *target = (sockaddr_in*) info->ai_addr;
				packet.Cat(0x01);
				packet.Cat((const char*) &target->sin_addr.s_addr, sizeof(uint32));
				packet.Cat((const char*) &target->sin_port, sizeof(uint16));
			}
			else
			if(info->ai_family == AF_INET6) {
				sockaddr_in6 *target = (sockaddr_in6*) info->ai_addr;
				packet.Cat(0x04);
				packet.Cat((const char*) &target->sin6_addr.s6_addr, byte(16));
				packet.Cat((const char*) &target->sin6_port, sizeof(uint16));
			}
			ipinfo.Clear();
		}
		LLOG(">> SOCKS5: Отправлка командного запроса.");
	}
	LDUMPHEX(packet);
	PutGet();
	return true;
}

bool NetProxy::Socks5ParseReply()
{
	if(packet_type == SOCKS5_HELO) {
		LLOG("<< SOCKS5: Получен ответ на приветствие сервера.");
		LDUMPHEX(packet);
		auto *p = (Reply::Helo*) packet.Begin();
		if(p->version != 0x05)
			SetError(INVALID_PACKET);
		if(p->method == 0x00)
			packet_type = SOCKS5_REQUEST;
		else
		if(p->method == 0x02)
			packet_type = SOCKS5_AUTH;
		else
			SetError(SOCKS5_INVALID_AUTHENTICATION_METHOD);
		return Socks5Request();
	}
	else
	if(packet_type == SOCKS5_AUTH) {
		LLOG("<< SOCKS5: Получен ответ по авторизации.");
		LDUMPHEX(packet);
		auto *p = (Reply::Auth*) packet.Begin();
		if(p->version != 0x01)
			SetError(INVALID_PACKET);
		if(p->status != 0x00)
			SetError(p->status);
		packet_type = SOCKS5_REQUEST;
		return Socks5Request();
	}
	else
	if(packet_type == SOCKS5_REQUEST) {
		LLOG("<< SOCKS5: Получен ответ на командный запрос.");
		LDUMPHEX(packet);
		auto *p = (Reply::Socks5*) packet.Begin();
		if(p->version != 0x05)
			SetError(INVALID_PACKET);
		if(p->status != 0x00)
			SetError(p->status);
		return SocksCommand(command);
	}
	NEVER();
	return true;
}

bool NetProxy::Socks5IsEof()
{
	auto n = packet.GetLength();
	if((packet_type == SOCKS5_HELO && n == sizeof(Reply::Helo))
	|| (packet_type == SOCKS5_AUTH && n == sizeof(Reply::Auth)))
		return Socks5ParseReply();
	if(packet_type == SOCKS5_REQUEST) {
		auto* p = (Reply::Socks5*) packet.Begin();
		const int header = 4;
		if(n == 5) {
			if(p->addrtype == 0x01)
				packet_length = header + sizeof(p->ipv4);		// 4 bytes for IPv4 address.
			else
			if(p->addrtype == 0x03)
				packet_length = header + p->namelen;			// 1 byte of name length (followed by 1–255 bytes the domain name).
			else
			if(p->addrtype == 0x04)
				packet_length = header + sizeof(p->ipv6);		// 16 bytes for IPv6 address.
			packet_length += int(2);							// 2 bytes for server bound port number.
		}
		if(n == packet_length) {
			return Socks5ParseReply();
		}
	}
	return false;
}

bool NetProxy::Connect(int type, const String& host, int port)
{
	target_host = host;
	target_port = port;
	proxy_type  = type;

	switch(proxy_type) {
		case HTTP:
			HttpcConnect();
			break;
		case SOCKS4:
			Socks4Connect(CONNECT);
			break;
		case SOCKS5:
			Socks5Connect(CONNECT);
			break;
		default:
			NEVER();
	};
	return Run();
}

bool NetProxy::Bind(int type, const String& host, int port)
{
	target_host = host;
	target_port = port;
	proxy_type  = type;

	switch(proxy_type) {
		case SOCKS4:
			Socks4Connect(BIND);
			break;
		case SOCKS5:
			Socks5Connect(BIND);
			break;
		default:{
			String err = GetMsg(HTTPCONNECT_NOBIND);
			error = MakeTuple<int, String>(10011, err);
			LLOG("Неудача. " << err);
			status = FAILED;
			return false;
		}
	};
	return Run();
}

bool NetProxy::Run()
{
	if(async)
		return true;
	while(Do());
	return !IsError();
}

bool NetProxy::Do()
{	try {
		Check();
		if(!queue.IsEmpty() && queue.Head()()) {
			queue.DropHead();
		}
		if(queue.IsEmpty()) {
			LLOG("Прокси-подключение успешно.");
			status = FINISHED;
			Exit();
		}
		else WhenDo();
	}
	catch(Error& e) {
		status = FAILED;
		queue.Clear();
		error = MakeTuple<int, String>(e.code, e);
		LLOG("не удалось. " << e);
		Exit();
	}
	return status == WORKING;
}

void NetProxy::ParseBoundAddr()
{
	int port   = 0;
	int family = 0;
	String ip;
	switch(proxy_type) {
		case SOCKS4: {
			auto *p = (Reply::Socks4*) packet.Begin();
			family = AF_INET;
			port = p->port;
			ip.Cat((char*) &p->address, sizeof(p->address));
			break;
		}
		case SOCKS5: {
			auto *p = (Reply::Socks5*) packet.Begin();
			port = (*(packet.Last() - sizeof(uint16)));
			switch(p->addrtype) {
				case 0x01: {
					family = AF_INET;
					ip.Cat((char*) &p->ipv4, sizeof(p->ipv4));
					break;
				}
				case 0x04: {
					family = AF_INET6;
					ip.Cat((char*) &p->ipv6, sizeof(p->ipv6));
					break;
				}
				case 0x03:
					return;
				default:
					NEVER();
			}
		}
	};
	String ip_buffer;
	if(!NtoP(family, ip, ip_buffer))
		throw Error(-1, Format("SOCKS%d: Неверный адрес BIN.", proxy_type));
	LLOG(Format("SOCKS%d: Bind успешен. [%s:%d]", proxy_type, ip_buffer, ntohs(port)));
	WhenBound(ip_buffer, ntohs(port));
}

NetProxy::NetProxy()
{
	socket = NULL;
	proxy_type = 0;
	start_time = 0;
	timeout = 60000;
	timeout_backup = 0;
	status = IDLE;
	async = false;
	ssl = false;
	lookup = false;
	bound = false;
	events = 0;
	proxy_type = HTTP;
	command = CONNECT;
}

NetProxy::~NetProxy()
{
}
}
