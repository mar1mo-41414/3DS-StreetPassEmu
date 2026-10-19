// StreetPass AES keyslot 0x2E oracle (network server).
//
// Static analysis hasn't recovered keyslot 0x2E's
// raw key bytes. This sidesteps that: libctru's PS_EncryptDecryptAes()
// wraps the same PS:EncryptDecryptAes call CECD uses, so this just runs the
// real console's crypto engine on a CTR the PC chooses (the PC already
// controls the CTR entirely, via the Hash Block -> HMAC-SHA1 step, see
// project findings) and reads back the resulting CCMP key. No need to
// ever know the key itself.
//
// Protocol: plain TCP on ORACLE_PORT. One connection at a time; per request,
// client sends exactly 16 bytes (the CTR), server replies with exactly 16
// bytes (AES-CTR(zero_block) under keyslot 0x2E for that CTR). Connection
// stays open for repeated requests. See src/streetpass_emu/oracle.py for
// the PC-side client.
//
// Verified 2026-09-09 against a real Old3DS (serial <serial>):
// ctr=00112233445566778899aabbccddeeff -> 76eb64cfd81af8e7f61147970221ed25
//.

#include <3ds.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <malloc.h>
#include <string.h>
#include <stdio.h>

#define SOC_ALIGN      0x1000
#define SOC_BUFFERSIZE 0x100000
#define ORACLE_PORT    17491

static u32 *SOC_buffer = NULL;

static bool recv_exact(int fd, u8 *buf, size_t len) {
	size_t got = 0;
	while (got < len) {
		ssize_t n = recv(fd, buf + got, len - got, 0);
		if (n <= 0) {
			return false;
		}
		got += (size_t)n;
	}
	return true;
}

static bool send_exact(int fd, const u8 *buf, size_t len) {
	size_t sent = 0;
	while (sent < len) {
		ssize_t n = send(fd, buf + sent, len - sent, 0);
		if (n <= 0) {
			return false;
		}
		sent += (size_t)n;
	}
	return true;
}

int main(int argc, char **argv) {
	gfxInitDefault();
	consoleInit(GFX_TOP, NULL);

	Result ps_rc = psInit();
	printf("StreetPass AES keyslot 0x2E oracle (network)\n");
	printf("psInit: 0x%08lx\n", (u32)ps_rc);

	SOC_buffer = (u32 *)memalign(SOC_ALIGN, SOC_BUFFERSIZE);
	Result soc_rc = socInit(SOC_buffer, SOC_BUFFERSIZE);
	printf("socInit: 0x%08lx\n", (u32)soc_rc);

	int listenfd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);

	struct sockaddr_in server;
	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_port = htons(ORACLE_PORT);
	server.sin_addr.s_addr = gethostid();

	bind(listenfd, (struct sockaddr *)&server, sizeof(server));
	fcntl(listenfd, F_SETFL, fcntl(listenfd, F_GETFL, 0) | O_NONBLOCK);
	listen(listenfd, 1);

	printf("listening on %s:%d\n", inet_ntoa(server.sin_addr), ORACLE_PORT);
	printf("START: exit\n\n");

	while (aptMainLoop()) {
		gspWaitForVBlank();
		hidScanInput();
		if (hidKeysDown() & KEY_START) {
			break;
		}

		struct sockaddr_in client;
		socklen_t clientlen = sizeof(client);
		int connfd = accept(listenfd, (struct sockaddr *)&client, &clientlen);
		if (connfd < 0) {
			continue;
		}

		fcntl(connfd, F_SETFL, fcntl(connfd, F_GETFL, 0) & ~O_NONBLOCK);
		printf("client connected: %s\n", inet_ntoa(client.sin_addr));

		u32 requests = 0;
		while (aptMainLoop()) {
			hidScanInput();
			if (hidKeysDown() & KEY_START) {
				close(connfd);
				close(listenfd);
				socExit();
				psExit();
				gfxExit();
				return 0;
			}

			u8 ctr[16];
			if (!recv_exact(connfd, ctr, sizeof(ctr))) {
				break;
			}

			u8 zero[16];
			memset(zero, 0, sizeof(zero));
			u8 result[16];
			PS_EncryptDecryptAes(16, zero, result, PS_ALGORITHM_CTR_ENC, PS_KEYSLOT_2E, ctr);

			if (!send_exact(connfd, result, sizeof(result))) {
				break;
			}
			requests++;
		}

		close(connfd);
		printf("client disconnected (%lu requests)\n", (unsigned long)requests);
	}

	close(listenfd);
	socExit();
	psExit();
	gfxExit();
	return 0;
}
