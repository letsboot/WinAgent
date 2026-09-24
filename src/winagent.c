/*
 * WinAgent — a chat window for Windows 95 that talks to a model on OpenRouter.
 *
 * Built on Linux with mingw-w64 (see build.sh). No C runtime: Windows 95 has no msvcrt.dll,
 * so the exe imports only kernel32, user32, gdi32 and wsock32 (Winsock 1.1).
 * TLS 1.2 comes from BearSSL, compiled into the exe. The OpenRouter key is asked for at
 * every start and kept only in memory.
 */
#include <windows.h>
#include <winsock.h>
#include "bearssl.h"
#include "ta.h"       /* TAs, TAs_NUM — trust anchors, see README */

#define OR_HOST "openrouter.ai"
#ifndef OR_MODEL
#define OR_MODEL "mistralai/mistral-nemo"
#endif
#ifndef OR_BUILD
#define OR_BUILD "dev"
#endif
/* OR_FALLBACK_IP (optional, -D at build time): used when the PC has no DNS */
#define ID_LOG 1
#define ID_INPUT 2
#define ID_SEND 3
#define ID_KEY 4
#define ID_MODEL 5
#define WM_ANSWER (WM_APP + 1)

/* ---- the few libc functions the compiler and BearSSL need ---- */
void *memcpy(void *d, const void *s, size_t n) { char *a = d; const char *b = s; while (n--) *a++ = *b++; return d; }
void *memmove(void *d, const void *s, size_t n) {
  char *a = d; const char *b = s;
  if (a < b) while (n--) *a++ = *b++; else { a += n; b += n; while (n--) *--a = *--b; }
  return d;
}
void *memset(void *d, int c, size_t n) { char *a = d; while (n--) *a++ = (char)c; return d; }
int memcmp(const void *x, const void *y, size_t n) {
  const unsigned char *a = x, *b = y;
  for (; n; n--, a++, b++) if (*a != *b) return *a - *b;
  return 0;
}
size_t strlen(const char *s) { size_t n = 0; while (s[n]) n++; return n; }

static char *cat(char *d, const char *s) { while (*s) *d++ = *s++; *d = 0; return d; }
static const char *find(const char *h, const char *n) {
  size_t k = strlen(n);
  for (; *h; h++) if (memcmp(h, n, k) == 0) return h;
  return 0;
}
static char *utoa(char *d, unsigned v) {
  char t[12]; int i = 0;
  do t[i++] = (char)('0' + v % 10); while (v /= 10);
  while (i) *d++ = t[--i];
  *d = 0; return d;
}

/* ---- conversation, kept as a JSON messages array ---- */
static const char SYSTEM_PROMPT[] =
  "You are WinAgent, an AI assistant running inside a Windows 95 PC in 1995. "
  "You are proud of your 16 colors and your 4 GB of RAM. Answer briefly and friendly, "
  "in plain text without markdown, 3 sentences at most.";

static char history[48000];   /* {"role":...},{"role":...} */
static char request[56000];
static char response[65536];
static char answer[16000];
static char token[256];        /* OpenRouter key, only in memory */
static char model[128] = OR_MODEL;
static HWND hwndMain, hwndLog, hwndInput, hwndSend;
static WNDPROC inputProc;

/* append a JSON string, turning Windows-1252 into UTF-8 */
static char *json_str(char *d, const char *s) {
  *d++ = '"';
  for (; *s; s++) {
    unsigned char c = (unsigned char)*s;
    if (c == '"' || c == '\\') { *d++ = '\\'; *d++ = (char)c; }
    else if (c == '\r') {}
    else if (c == '\n') { *d++ = '\\'; *d++ = 'n'; }
    else if (c < 0x20) *d++ = ' ';
    else if (c < 0x80) *d++ = (char)c;
    else { *d++ = (char)(0xC0 | (c >> 6)); *d++ = (char)(0x80 | (c & 0x3F)); }
  }
  *d++ = '"'; *d = 0;
  return d;
}

static void history_add(const char *role, const char *text) {
  char *d;
  if (strlen(history) + strlen(text) * 2 + 64 > sizeof(history)) history[0] = 0;  /* forget old turns */
  d = history + strlen(history);
  if (history[0]) *d++ = ',';
  d = cat(d, "{\"role\":\""); d = cat(d, role); d = cat(d, "\",\"content\":");
  d = json_str(d, text); cat(d, "}");
}

/* decode the JSON string at s into Windows-1252 text with CRLF line ends */
static void json_decode(char *d, const char *s, size_t max) {
  char *end = d + max - 4;
  while (*s && *s != '"' && d < end) {
    unsigned c = (unsigned char)*s++;
    if (c == '\\') {
      c = (unsigned char)*s++;
      if (c == 'n') { *d++ = '\r'; *d++ = '\n'; continue; }
      if (c == 't') c = ' ';
      else if (c == 'u') {
        unsigned v = 0; int i;
        for (i = 0; i < 4 && *s; i++, s++) v = v * 16 + (*s <= '9' ? *s - '0' : (*s | 32) - 'a' + 10);
        c = v;
      } else if (c == 'r') continue;
    } else if (c >= 0xC0) {           /* UTF-8 sequence */
      unsigned n = c >= 0xF0 ? 3 : c >= 0xE0 ? 2 : 1;
      c &= 0x3F >> n;
      while (n-- && (*s & 0xC0) == 0x80) c = (c << 6) | (*s++ & 0x3F);
    }
    *d++ = c < 0x100 ? (char)c : c == 0x2019 || c == 0x2018 ? '\'' : c == 0x201C || c == 0x201D ? '"'
         : c == 0x2013 || c == 0x2014 ? '-' : '?';
  }
  *d = 0;
}

/* ---- TLS over Winsock 1.1 ---- */
static int sock_read(void *ctx, unsigned char *buf, size_t len) {
  int n = recv(*(SOCKET *)ctx, (char *)buf, (int)len, 0);
  return n <= 0 ? -1 : n;
}
static int sock_write(void *ctx, const unsigned char *buf, size_t len) {
  int n = send(*(SOCKET *)ctx, (const char *)buf, (int)len, 0);
  return n <= 0 ? -1 : n;
}

static br_ssl_client_context sc;
static br_x509_minimal_context xc;
static unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];

/* no crypto RNG on Windows 95: hash timer jitter, cursor and time into a seed */
static void seed(unsigned char out[32]) {
  br_sha256_context h; LARGE_INTEGER q; POINT p; SYSTEMTIME st; DWORD t; int i;
  br_sha256_init(&h);
  for (i = 0; i < 2000; i++) {
    QueryPerformanceCounter(&q); br_sha256_update(&h, &q, sizeof q);
    t = GetTickCount(); br_sha256_update(&h, &t, sizeof t);
  }
  GetCursorPos(&p); br_sha256_update(&h, &p, sizeof p);
  GetSystemTime(&st); br_sha256_update(&h, &st, sizeof st);
  br_sha256_update(&h, &h, sizeof h);
  br_sha256_out(&h, out);
}

static const char *chat(void) {
  static WSADATA wsa; static int wsa_ok;
  br_sslio_context ioc; struct sockaddr_in sa; struct hostent *he; SOCKET s;
  unsigned char rnd[32]; FILETIME ft; unsigned long long secs; char *d; size_t len, got = 0; int n, err;
  const char *p;

  if (!wsa_ok && WSAStartup(MAKEWORD(1, 1), &wsa) != 0) return "Winsock did not start.";
  wsa_ok = 1;

  /* request body and headers */
  d = cat(response, "{\"model\":"); d = json_str(d, model);
  d = cat(d, ",\"max_tokens\":400,\"messages\":[{\"role\":\"system\",\"content\":");
  d = json_str(d, SYSTEM_PROMPT); d = cat(d, "},"); d = cat(d, history); cat(d, "]}");
  len = strlen(response);
  d = cat(request, "POST /api/v1/chat/completions HTTP/1.0\r\nHost: " OR_HOST "\r\nAuthorization: Bearer ");
  d = cat(d, token);
  d = cat(d, "\r\nContent-Type: application/json\r\n"
             "HTTP-Referer: https://github.com/letsboot/WinAgent\r\nX-Title: WinAgent for Windows 95\r\n"
             "Content-Length: ");
  d = utoa(d, (unsigned)len); d = cat(d, "\r\n\r\n"); cat(d, response);

  memset(&sa, 0, sizeof sa);
  sa.sin_family = AF_INET; sa.sin_port = htons(443);
  he = gethostbyname(OR_HOST);
  if (he) memcpy(&sa.sin_addr, he->h_addr_list[0], 4);
#ifdef OR_FALLBACK_IP
  else sa.sin_addr.s_addr = inet_addr(OR_FALLBACK_IP);
#else
  else return "Cannot resolve openrouter.ai (no DNS?).";
#endif
  s = socket(AF_INET, SOCK_STREAM, 0);
  if (s == INVALID_SOCKET) return "No socket.";
  if (connect(s, (struct sockaddr *)&sa, sizeof sa) != 0) { closesocket(s); return "Cannot connect to openrouter.ai:443."; }

  br_ssl_client_init_full(&sc, &xc, TAs, TAs_NUM);
  GetSystemTimeAsFileTime(&ft);
  secs = ((((unsigned long long)ft.dwHighDateTime) << 32) | ft.dwLowDateTime) / 10000000ULL - 11644473600ULL;
  br_x509_minimal_set_time(&xc, (uint32_t)(secs / 86400 + 719528), (uint32_t)(secs % 86400));
  br_ssl_engine_set_buffer(&sc.eng, iobuf, sizeof iobuf, 1);
  seed(rnd); br_ssl_engine_inject_entropy(&sc.eng, rnd, sizeof rnd);
  br_ssl_client_reset(&sc, OR_HOST, 0);
  br_sslio_init(&ioc, &sc.eng, sock_read, &s, sock_write, &s);

  br_sslio_write_all(&ioc, request, strlen(request));
  br_sslio_flush(&ioc);
  while (got < sizeof(response) - 1 && (n = br_sslio_read(&ioc, response + got, sizeof(response) - 1 - got)) > 0) got += n;
  response[got] = 0;
  br_sslio_close(&ioc);
  closesocket(s);

  err = br_ssl_engine_last_error(&sc.eng);
  if (got == 0) {
    d = cat(answer, "TLS error "); utoa(d, (unsigned)err);
    return answer;
  }
  if ((p = find(response, "\"content\":\"")) != 0) { json_decode(answer, p + 11, sizeof answer); return answer; }
  if ((p = find(response, "\"message\":\"")) != 0) { d = cat(answer, "OpenRouter says: "); json_decode(d, p + 11, 400); return answer; }
  return "No answer in the response.";
}

/* ---- window ---- */
static void log_append(const char *who, const char *text) {
  int n = GetWindowTextLengthA(hwndLog);
  if (n > 28000) { SetWindowTextA(hwndLog, ""); n = 0; }
  SendMessageA(hwndLog, EM_SETSEL, n, n);
  SendMessageA(hwndLog, EM_REPLACESEL, 0, (LPARAM)who);
  SendMessageA(hwndLog, EM_REPLACESEL, 0, (LPARAM)text);
  SendMessageA(hwndLog, EM_REPLACESEL, 0, (LPARAM)"\r\n\r\n");
  SendMessageA(hwndLog, EM_SCROLLCARET, 0, 0);
}

static DWORD WINAPI worker(LPVOID arg) {
  (void)arg;
  PostMessageA(hwndMain, WM_ANSWER, 0, (LPARAM)chat());
  return 0;
}

static void send_prompt(void) {
  static char text[2000]; DWORD tid;
  if (!IsWindowEnabled(hwndSend)) return;
  GetWindowTextA(hwndInput, text, sizeof text);
  if (!text[0]) return;
  SetWindowTextA(hwndInput, "");
  log_append("You: ", text);
  history_add("user", text);
  EnableWindow(hwndSend, FALSE);
  SetWindowTextA(hwndMain, "WinAgent - thinking...");
  CreateThread(0, 0, worker, 0, 0, &tid);
}

/* Enter in the input box sends */
static LRESULT CALLBACK input_proc(HWND h, UINT m, WPARAM w, LPARAM l) {
  if (m == WM_CHAR && w == '\r') { send_prompt(); return 0; }
  return CallWindowProcA(inputProc, h, m, w, l);
}

static LRESULT CALLBACK wnd_proc(HWND h, UINT m, WPARAM w, LPARAM l) {
  HFONT font = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
  switch (m) {
  case WM_CREATE:
    hwndLog = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
      WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL, 0, 0, 0, 0, h, (HMENU)ID_LOG, 0, 0);
    hwndInput = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
      WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL, 0, 0, 0, 0, h, (HMENU)ID_INPUT, 0, 0);
    hwndSend = CreateWindowExA(0, "BUTTON", "&Send", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
      0, 0, 0, 0, h, (HMENU)ID_SEND, 0, 0);
    SendMessageA(hwndLog, WM_SETFONT, (WPARAM)font, 0);
    SendMessageA(hwndInput, WM_SETFONT, (WPARAM)font, 0);
    SendMessageA(hwndSend, WM_SETFONT, (WPARAM)font, 0);
    inputProc = (WNDPROC)SetWindowLongA(hwndInput, GWL_WNDPROC, (LONG)input_proc);
    { char hello[300], *d = cat(hello, "Hello! I am WinAgent, an AI agent for Windows 95. Model: ");
      d = cat(d, model); cat(d, ", TLS 1.2 by BearSSL, build " OR_BUILD ". Ask me anything.");
      log_append("WinAgent: ", hello); }
    SetFocus(hwndInput);
    return 0;
  case WM_SIZE: {
    int cw = LOWORD(l), ch = HIWORD(l);
    MoveWindow(hwndLog, 8, 8, cw - 16, ch - 52, TRUE);
    MoveWindow(hwndInput, 8, ch - 36, cw - 104, 26, TRUE);
    MoveWindow(hwndSend, cw - 88, ch - 37, 80, 28, TRUE);
    return 0;
  }
  case WM_SETFOCUS: SetFocus(hwndInput); return 0;
  case WM_COMMAND:
    if (LOWORD(w) == ID_SEND) send_prompt();
    return 0;
  case WM_ANSWER:
    log_append("WinAgent: ", (const char *)l);
    if ((const char *)l == answer && find(answer, "OpenRouter says") != answer && find(answer, "TLS error") != answer) history_add("assistant", answer);
    EnableWindow(hwndSend, TRUE);
    SetWindowTextA(hwndMain, "WinAgent");
    SetFocus(hwndInput);
    return 0;
  case WM_DESTROY: PostQuitMessage(0); return 0;
  }
  return DefWindowProcA(h, m, w, l);
}

/* ---- start window: asks for the OpenRouter key and the model ---- */
static HWND hwndKey, hwndModel;
static int keyDone;   /* 0 = open, 1 = OK, -1 = cancelled */

static LRESULT CALLBACK key_proc(HWND h, UINT m, WPARAM w, LPARAM l) {
  HFONT font = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
  HWND c;
  switch (m) {
  case WM_CREATE:
#define CHILD(ex, cls, text, style, x, y, cw, ch, id) \
    c = CreateWindowExA(ex, cls, text, WS_CHILD | WS_VISIBLE | (style), x, y, cw, ch, h, (HMENU)(id), 0, 0); \
    SendMessageA(c, WM_SETFONT, (WPARAM)font, 0);
    CHILD(0, "STATIC", "Enter your OpenRouter API key (get one at openrouter.ai/keys). "
                       "It stays in memory and is gone when WinAgent closes.", 0, 12, 10, 330, 32, 0)
    CHILD(0, "STATIC", "API &key:", 0, 12, 52, 60, 16, 0)
    CHILD(WS_EX_CLIENTEDGE, "EDIT", "", WS_TABSTOP | ES_AUTOHSCROLL | ES_PASSWORD, 76, 48, 266, 22, ID_KEY)
    hwndKey = c;
    SendMessageA(c, EM_LIMITTEXT, sizeof token - 1, 0);
    CHILD(0, "STATIC", "&Model:", 0, 12, 82, 60, 16, 0)
    CHILD(WS_EX_CLIENTEDGE, "EDIT", model, WS_TABSTOP | ES_AUTOHSCROLL, 76, 78, 266, 22, ID_MODEL)
    hwndModel = c;
    SendMessageA(c, EM_LIMITTEXT, sizeof model - 1, 0);
    CHILD(0, "BUTTON", "OK", WS_TABSTOP | BS_DEFPUSHBUTTON, 176, 112, 80, 26, IDOK)
    CHILD(0, "BUTTON", "Cancel", WS_TABSTOP, 262, 112, 80, 26, IDCANCEL)
#undef CHILD
    SetFocus(hwndKey);
    return 0;
  case WM_COMMAND:
    if (LOWORD(w) == IDOK) {
      GetWindowTextA(hwndKey, token, sizeof token);
      if (!token[0]) { SetFocus(hwndKey); return 0; }
      GetWindowTextA(hwndModel, model, sizeof model);
      if (!model[0]) cat(model, OR_MODEL);
      SetWindowTextA(hwndKey, "");
      keyDone = 1; DestroyWindow(h);
    } else if (LOWORD(w) == IDCANCEL) DestroyWindow(h);
    return 0;
  case WM_CLOSE: DestroyWindow(h); return 0;
  case WM_DESTROY: if (!keyDone) keyDone = -1; return 0;
  }
  return DefWindowProcA(h, m, w, l);
}

static int ask_key(HINSTANCE inst) {
  WNDCLASSA wc; MSG msg; RECT r = { 0, 0, 354, 150 }; HWND h;
  DWORD style = WS_CAPTION | WS_SYSMENU | WS_POPUP;
  memset(&wc, 0, sizeof wc);
  wc.lpfnWndProc = key_proc; wc.hInstance = inst; wc.lpszClassName = "WinAgentKey";
  wc.hCursor = LoadCursorA(0, (LPCSTR)IDC_ARROW); wc.hIcon = LoadIconA(0, (LPCSTR)IDI_APPLICATION);
  wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
  RegisterClassA(&wc);
  AdjustWindowRectEx(&r, style, FALSE, WS_EX_DLGMODALFRAME);
  h = CreateWindowExA(WS_EX_DLGMODALFRAME, "WinAgentKey", "WinAgent - OpenRouter key", style,
    120, 100, r.right - r.left, r.bottom - r.top, 0, 0, inst, 0);
  ShowWindow(h, SW_SHOWNORMAL);
  /* IsDialogMessage gives Tab, Enter (IDOK) and Esc (IDCANCEL) like a real dialog */
  while (!keyDone && GetMessageA(&msg, 0, 0, 0) > 0)
    if (!IsDialogMessageA(h, &msg)) { TranslateMessage(&msg); DispatchMessageA(&msg); }
  return keyDone == 1;
}

int WINAPI WinMain(HINSTANCE inst, HINSTANCE prev, LPSTR cmd, int show) {
  WNDCLASSA wc; MSG msg;
  (void)prev; (void)cmd;
  if (!ask_key(inst)) return 0;
  memset(&wc, 0, sizeof wc);
  wc.lpfnWndProc = wnd_proc; wc.hInstance = inst; wc.lpszClassName = "WinAgent";
  wc.hCursor = LoadCursorA(0, (LPCSTR)IDC_ARROW); wc.hIcon = LoadIconA(0, (LPCSTR)IDI_APPLICATION);
  wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
  RegisterClassA(&wc);
  hwndMain = CreateWindowExA(0, "WinAgent", "WinAgent", WS_OVERLAPPEDWINDOW, 80, 60, 560, 420, 0, 0, inst, 0);
  ShowWindow(hwndMain, show);
  while (GetMessageA(&msg, 0, 0, 0) > 0) { TranslateMessage(&msg); DispatchMessageA(&msg); }
  return (int)msg.wParam;
}

void WinMainCRTStartup(void) {
  ExitProcess(WinMain(GetModuleHandleA(0), 0, 0, SW_SHOWNORMAL));
}
