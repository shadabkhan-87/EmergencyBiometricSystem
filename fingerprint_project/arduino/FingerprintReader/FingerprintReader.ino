#include <Wire.h> 
#include <LiquidCrystal_I2C.h>

// Set the LCD address to 0x27 for a 16 chars and 2 line display
LiquidCrystal_I2C lcd(0x27, 16, 2);

#include <SoftwareSerial.h>
SoftwareSerial fingerPrint(2, 3);

#include <Servo.h>
Servo myServo;

#include <Adafruit_Fingerprint.h>
uint8_t id;
Adafruit_Fingerprint finger = Adafruit_Fingerprint(&fingerPrint);

#define enroll A0
#define del A1
#define up A2
#define down A3

const int relay1 = 8;
const int relay2 = 9;
const int buzzer  = 10;

void setup() 
{
  lcd.begin();
  lcd.backlight();

  pinMode(relay1, OUTPUT);
  pinMode(relay2, OUTPUT);
  pinMode(buzzer, OUTPUT);
  delay(1000);
  digitalWrite(relay1, LOW);
  digitalWrite(relay2, LOW);

  pinMode(enroll, INPUT_PULLUP);
  pinMode(up, INPUT_PULLUP); 
  pinMode(down, INPUT_PULLUP); 
  pinMode(del, INPUT_PULLUP); 

  lcd.clear();
  lcd.print("FP  BASED Vehicle");
  lcd.setCursor(0,1);
  lcd.print("Ignition Control");
  delay(2000);

  finger.begin(57600);

  // IMPORTANT: set USB Serial to 57600 so Node server (57600) can read lines
  Serial.begin(57600);
  lcd.clear();
  lcd.print("Finding Module");
  Serial.print("Finding Module..");
  lcd.setCursor(0,1);
  delay(1000);

  if (finger.verifyPassword()) 
  {
    Serial.println("Found fingerprint sensor!");
    lcd.clear();
    lcd.print("Found Module ");
    delay(1000);
  } 
  else 
  {
    Serial.println("Did not find fingerprint sensor :(");
    lcd.clear();
    lcd.print("module not Found");
    lcd.setCursor(0,1);
    lcd.print("Check Connections");
    while (1);
  }
}

void loop() 
{
  lcd.setCursor(0,0);
  lcd.print("Press UP/Down ");
  lcd.setCursor(0,1);
  lcd.print("to start System");

  if (digitalRead(up) == 0 || digitalRead(down) == 0)
  {
    digitalWrite(relay1, LOW);
    digitalWrite(relay2, LOW);

    for (int i = 0; i < 5; i++)
    {
      lcd.clear();
      lcd.print("Place Finger");
      delay(2000);

      int result = getFingerprintIDez();
      if (result >= 0)
      {
        digitalWrite(relay1, LOW);
        digitalWrite(relay2, HIGH);
        lcd.clear();
        lcd.print("Allowed");
        lcd.setCursor(0,1);
        lcd.print("ignition On");
        delay(5000);
        return;
      }
    }
  }

  checkKeys();
  delay(1000);
}

void checkKeys()
{
  if (digitalRead(enroll) == 0)
  {
    lcd.clear();
    lcd.print("Please Wait");
    delay(1000);
    while (digitalRead(enroll) == 0);
    Enroll();
  }
  else if (digitalRead(del) == 0)
  {
    lcd.clear();
    lcd.print("Please Wait");
    delay(1000);
    delet();
  }  
}

void Enroll()
{
  int count = 0;
  lcd.clear();
  lcd.print("Enroll Finger    ");
  lcd.setCursor(0,1);
  lcd.print("Location:");
  while (1)
  {
    lcd.setCursor(9,1);
    lcd.print(count);
    if (digitalRead(up) == 0)
    {
      count++;
      if (count > 25) count = 0;
      delay(500);
    }
    else if (digitalRead(down) == 0)
    {
      count--;
      if (count < 0) count = 25;
      delay(500);
    }
    else if (digitalRead(del) == 0)
    {
      id = count;
      getFingerprintEnroll();
      return;
    }
    else if (digitalRead(enroll) == 0)
    {        
      return;
    }
  }
}

void delet()
{
  int count = 0;
  lcd.clear();
  lcd.print("Delete Finger    ");
  lcd.setCursor(0,1);
  lcd.print("Location:");
  while (1)
  {
    lcd.setCursor(9,1);
    lcd.print(count);
    if (digitalRead(up) == 0)
    {
      count++;
      if (count > 25) count = 0;
      delay(500);
    }
    else if (digitalRead(down) == 0)
    {
      count--;
      if (count < 0) count = 25;
      delay(500);
    }
    else if (digitalRead(del) == 0)
    {
      id = count;
      deleteFingerprint(id);
      return;
    }
    else if (digitalRead(enroll) == 0)
    {        
      return;
    }
  }
}

uint8_t getFingerprintEnroll() 
{
  int p = -1;
  lcd.clear();
  lcd.print("finger ID:");
  lcd.print(id);
  lcd.setCursor(0,1);
  lcd.print("Place Finger");
  delay(2000);

  while (p != FINGERPRINT_OK)
  {
    p = finger.getImage();
    switch (p)
    {
      case FINGERPRINT_OK:
        Serial.println("Image taken");
        lcd.clear();
        lcd.print("Image taken");
        break;
      case FINGERPRINT_NOFINGER:
        Serial.println("No Finger");
        lcd.clear();
        lcd.print("No Finger");
        break;
      case FINGERPRINT_PACKETRECIEVEERR:
        Serial.println("Communication error");
        lcd.clear();
        lcd.print("Comm Error");
        break;
      case FINGERPRINT_IMAGEFAIL:
        Serial.println("Imaging error");
        lcd.clear();
        lcd.print("Imaging Error");
        break;
      default:
        Serial.println("Unknown error");
        lcd.clear();
        lcd.print("Unknown Error");
        break;
    }
  }

  p = finger.image2Tz(1);
  switch (p) {
    case FINGERPRINT_OK:
      Serial.println("Image converted");
      lcd.clear();
      lcd.print("Image converted");
      break;
    case FINGERPRINT_IMAGEMESS:
      Serial.println("Image too messy");
      lcd.clear();
      lcd.print("Image too messy");
      return p;
    case FINGERPRINT_PACKETRECIEVEERR:
      Serial.println("Communication error");
      lcd.clear();
      lcd.print("Comm Error");
      return p;
    case FINGERPRINT_FEATUREFAIL:
    case FINGERPRINT_INVALIDIMAGE:
      Serial.println("Could not find fingerprint features");
      lcd.clear();
      lcd.print("Feature Not Found");
      return p;
    default:
      Serial.println("Unknown error");
      lcd.clear();
      lcd.print("Unknown Error");
      return p;
  }

  Serial.println("Remove finger");
  lcd.clear();
  lcd.print("Remove Finger");
  delay(2000);
  p = 0;
  while (p != FINGERPRINT_NOFINGER) {
    p = finger.getImage();
  }

  Serial.print("ID "); Serial.println(id);
  p = -1;
  Serial.println("Place same finger again");
  lcd.clear();
  lcd.print("Place Finger");
  lcd.setCursor(0,1);
  lcd.print("   Again");

  while (p != FINGERPRINT_OK) {
    p = finger.getImage();
    switch (p) {
      case FINGERPRINT_OK:
        Serial.println("Image taken");
        break;
      case FINGERPRINT_NOFINGER:
        Serial.print(".");
        break;
      case FINGERPRINT_PACKETRECIEVEERR:
        Serial.println("Communication error");
        break;
      case FINGERPRINT_IMAGEFAIL:
        Serial.println("Imaging error");
        break;
      default:
        Serial.println("Unknown error");
        return p;
    }
  }

  p = finger.image2Tz(2);
  switch (p) {
    case FINGERPRINT_OK:
      Serial.println("Image converted");
      break;
    case FINGERPRINT_IMAGEMESS:
      Serial.println("Image too messy");
      return p;
    case FINGERPRINT_PACKETRECIEVEERR:
      Serial.println("Communication error");
      return p;
    case FINGERPRINT_FEATUREFAIL:
    case FINGERPRINT_INVALIDIMAGE:
      Serial.println("Could not find fingerprint features");
      return p;
    default:
      Serial.println("Unknown error");
      return p;
  }

  Serial.print("Creating model for #");  Serial.println(id);
  p = finger.createModel();

  if (p == FINGERPRINT_OK) {
    Serial.println("Prints matched!");
  } else if (p == FINGERPRINT_PACKETRECIEVEERR) {
    Serial.println("Communication error");
    Serial.print("ENROLL_FAIL:"); Serial.println(id);
    return p;
  } else if (p == FINGERPRINT_ENROLLMISMATCH) {
    Serial.println("Fingerprints did not match");
    Serial.print("ENROLL_FAIL:"); Serial.println(id);
    return p;
  } else {
    Serial.println("Unknown error");
    Serial.print("ENROLL_FAIL:"); Serial.println(id);
    return p;
  }   

  Serial.print("ID "); Serial.println(id);
  p = finger.storeModel(id);

  if (p == FINGERPRINT_OK) {
    Serial.println("Stored!");
    lcd.clear();
    lcd.print("Stored!");
    delay(2000);
    // Notify host/server that enrollment completed
    Serial.print("ENROLLED:"); Serial.println(id);
  } else if (p == FINGERPRINT_PACKETRECIEVEERR) {
    Serial.println("Communication error");
    Serial.print("ENROLL_FAIL:"); Serial.println(id);
    return p;
  } else if (p == FINGERPRINT_BADLOCATION) {
    Serial.println("Could not store in that location");
    Serial.print("ENROLL_FAIL:"); Serial.println(id);
    return p;
  } else if (p == FINGERPRINT_FLASHERR) {
    Serial.println("Error writing to flash");
    Serial.print("ENROLL_FAIL:"); Serial.println(id);
    return p;
  } else {
    Serial.println("Unknown error");
    Serial.print("ENROLL_FAIL:"); Serial.println(id);
    return p;
  }   
}

int getFingerprintIDez()
{
  uint8_t p = finger.getImage();
  if (p != FINGERPRINT_OK) return -1;

  p = finger.image2Tz();
  if (p != FINGERPRINT_OK) return -1;

  p = finger.fingerFastSearch();
  if (p != FINGERPRINT_OK)
  {
    lcd.clear();
    lcd.print("Finger Not Found");
    lcd.setCursor(0,1);
    lcd.print("Try Later");
    digitalWrite(buzzer, HIGH);
    delay(2000);  
    digitalWrite(buzzer, LOW);
    return -1;
  }

  // found a match!
  Serial.print("MATCHED:"); 
  Serial.println(finger.fingerID);
  Serial.print("Found ID #"); 
  Serial.print(finger.fingerID); 
  return finger.fingerID; 
}

uint8_t deleteFingerprint(uint8_t id) 
{
  uint8_t p = -1;  
  lcd.clear();
  lcd.print("Please wait");
  p = finger.deleteModel(id);

  if (p == FINGERPRINT_OK) 
  {
    Serial.println("Deleted!");
    lcd.clear();
    lcd.print("Figer Deleted");
    lcd.setCursor(0,1);
    lcd.print("Successfully");
    delay(1000);
    // Notify host/server that deletion completed
    Serial.print("DELETED:"); Serial.println(id);
    return p;
  } 
  else 
  {
    Serial.print("Something Wrong"); 
    lcd.clear();
    lcd.print("Something Wrong");
    lcd.setCursor(0,1);
    lcd.print("Try Again Later");
    delay(2000);
    Serial.print("DELETE_FAIL:"); Serial.println(id);
    return p;
  }   
}
