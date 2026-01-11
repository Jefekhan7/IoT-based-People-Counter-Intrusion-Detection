#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include "mbedtls/aes.h"
#include <base64.h>

#define IR1 25
#define IR2 26
#define BUZZER 27

const char* WIFI_SSID = "yourwifi_ssid";
const char* WIFI_PASS = "yourwifipassword";
const char* SERVER_URL = "http://serverip:5000/event";
const char* AUTH_TOKEN = "SECRET_TOKEN";

unsigned char AES_KEY[16] = {
  0x10,0x21,0x32,0x43,0x54,0x65,0x76,0x87,
  0x98,0xA9,0xBA,0xCB,0xDC,0xED,0xFE,0x0F
};

bool armed = true;           // Local copy, synced from server
int people = 0;
uint32_t eventCounter = 0;

unsigned long t1 = 0;
unsigned long t2 = 0;

enum State {IDLE, SEEN_IR1, SEEN_IR2};
State state = IDLE;

unsigned long lastArmCheck = 0;

// ---------------- BUZZER (3.5 second alert) ----------------
void intrusionBeep() {
  digitalWrite(BUZZER, HIGH);
  delay(3500);
  digitalWrite(BUZZER, LOW);
}

// ---------------- AES ENCRYPTION (zero padding) ----------------
String encryptAES(String plain) {
  int len = plain.length();
  int paddedLen = ((len + 15) / 16) * 16;

  unsigned char input[paddedLen];
  unsigned char output[paddedLen];

  memset(input, 0, paddedLen);
  memcpy(input, plain.c_str(), len);

  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);
  mbedtls_aes_setkey_enc(&ctx, AES_KEY, 128);

  for (int i = 0; i < paddedLen; i += 16) {
    mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, input + i, output + i);
  }

  mbedtls_aes_free(&ctx);
  return base64::encode(output, paddedLen);
}

// ---------------- CHECKSUM ----------------
String checksum(String s) {
  uint32_t sum = 0;
  for (char c : s) sum += (unsigned char)c;
  return String(sum, HEX);
}

// ---------------- SEND EVENT ----------------
void sendEvent(String type, bool intrusion) {
  StaticJsonDocument<256> doc;
  doc["device"] = "ESP32-IDS-01";
  doc["type"] = type;
  doc["people"] = people;
  doc["armed"] = armed;
  doc["intrusion"] = intrusion;
  doc["seq"] = eventCounter++;

  String plain;
  serializeJson(doc, plain);

  String cipher = encryptAES(plain);
  String hmac = checksum(cipher);

  StaticJsonDocument<256> out;
  out["cipher"] = cipher;
  out["hmac"] = hmac;

  String payload;
  serializeJson(out, payload);

  HTTPClient http;
  http.begin(SERVER_URL);
  http.addHeader("Content-Type", "application/json");
  http.addHeader("Authorization", "Bearer SECRET_TOKEN");

  http.POST(payload);
  http.end();
}

// ---------------- SYNC ARMED STATE FROM SERVER ----------------
void updateArmedFromServer() {
  HTTPClient http;
  http.begin("http://10.149.40.29:5000/summary");
  http.addHeader("Authorization", "Bearer SECRET_TOKEN");

  int code = http.GET();
  if (code == 200) {
    String resp = http.getString();
    StaticJsonDocument<256> doc;
    deserializeJson(doc, resp);
    armed = doc["armed"].as<bool>();
  }
  http.end();
}

// ---------------- SETUP ----------------
void setup() {
  pinMode(IR1, INPUT);
  pinMode(IR2, INPUT);
  pinMode(BUZZER, OUTPUT);
  digitalWrite(BUZZER, LOW);

  Serial.begin(921600);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) delay(500);
  
  updateArmedFromServer();
  sendEvent("SYSTEM_BOOT", false);
}

// ---------------- MAIN LOOP ----------------
void loop() {
  unsigned long now = millis();

  // Sync armed state every 5 seconds
  if (now - lastArmCheck > 5000) {
    updateArmedFromServer();
    lastArmCheck = now;
  }

  bool ir1 = digitalRead(IR1);  // HIGH = beam broken
  bool ir2 = digitalRead(IR2);

  switch (state) {
    case IDLE:
      if (ir1 && !ir2) {
        state = SEEN_IR1;
        t1 = now;
      } else if (ir2 && !ir1) {
        state = SEEN_IR2;
        t2 = now;
      }
      break;

    case SEEN_IR1:
      if (!ir1 && !ir2) {
        state = IDLE;  // Reset when clear
      } else if (ir2 && now - t1 < 1000) {  // Valid crossing
        if (armed) {
          intrusionBeep();
          sendEvent("INTRUSION_ENTRY", true);
        } else {
          people++;
          sendEvent("ENTRY", false);
        }
        state = IDLE;
      } else if (now - t1 > 1000) {  // Lingering in IR1
        if (armed) {
          intrusionBeep();
          sendEvent("INTRUSION_SINGLE_IR1", true);
        }
        state = IDLE;
      }
      break;

    case SEEN_IR2:
      if (!ir1 && !ir2) {
        state = IDLE;
      } else if (ir1 && now - t2 < 1000) {  // Valid exit
        if (armed) {
          intrusionBeep();
          sendEvent("INTRUSION_EXIT", true);
        } else {
          if (people > 0) people--;
          sendEvent("EXIT", false);
        }
        state = IDLE;
      } else if (now - t2 > 1000) {  // Lingering in IR2
        if (armed) {
          intrusionBeep();
          sendEvent("INTRUSION_SINGLE_IR2", true);
        }
        state = IDLE;
      }
      break;
  }

  delay(20);
}