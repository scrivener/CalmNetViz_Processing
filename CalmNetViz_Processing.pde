g/**
 * Carnivore Client 
 * by Alexander R. Galloway. 
 
 * The Carnivore library for Processing allows the programmer to run a packet 
 * sniffer from within the Processing environment. A packet sniffer is any 
 * application that is able to indiscriminately eavesdrop on data traffic 
 * traveling through a local area network (LAN).
 * 
 * Note: requires Carnivore Library for Processing v2.2 (http://r-s-g.org/carnivore)
 * Windows, first install winpcap (http://winpcap.org)
 * Mac, first open a Terminal and execute this commmand: sudo chmod 777 /dev/bpf*
 * (must be done each time you reboot your mac)
 */

import de.bezier.data.sql.*;
import java.util.Iterator;
import java.util.Date;
import java.util.Calendar;
import org.rsg.carnivore.*;
import org.rsg.carnivore.net.*;
import org.rsg.lib.Log;

SQLite db;

HashMap<IPAddress, pin> pins = new HashMap<IPAddress, pin>();
HashSet<String> countries = new HashSet<String>();
HashSet<String> cities = new HashSet<String>();

PImage mapImage;

float shrinkSpeed = 0.97;
int splitter, x, y;
PFont font;
int ctr = 0;
int average[];
int avgBin = 0;
int newPackets = 0;

private final int mapX = 100;
private final int mapY = 200;

private final int WIDTH = 800;
private final int HEIGHT = 600;

private final int DEAD_TIMER_CAP = 10;  //10 frames after losing the last of its bytes, a pin vanishes

private class pin {
  public float lat;
  public float lon;
  
  public String country;
  public String city;
 
  public PImage mapImage;
  public float x;
  public float y; 
  
  public int bytes = 0;
  
  private int deadTimer = 0;
  
  public Pin(PImage mapImage, float lat, float lon, String country, String city) {
    this.mapImage = mapImage;
    this.x = map(lon, -180, 180, 100, mapX+mapImage.width);
    this.y = map(lat, 90, -90, 200, mapY+mapImage.height);
    this.lat = lat;
    this.lon = lon;
    this.country = country;
    this.city = city;
    
//    this.size = DEFAULT_PIN_SIZE;
  }
  public boolean drawSelf() {
    int rad = Math.log(bytes);
    if (bytes > 0) {
      fill(0xff, 0xff, 0x00);
      ellipse(this.x, this.y, rad, rad);
      return true;
    }
    else if (deadTimer <= DEAD_TIMER_CAP) {
      fill(0xff, 0xff, 0x00, 0x88);  //no bytes left in window - display as transparent
      ellipse(this.x, this.y, rad, rad);
      deadTimer++;
      return true;
    }
    else {
      return false;
    }
    
  }
  public void addBytes(int bytes) {
    this.bytes += bytes;
    if (bytes > 0) {
      deadTimer = 0; 
    }
  }
  public void subBytes(int bytes) {
    this.bytes -= bytes; 
  }
}


private class pkt {
  public Date time;
  public int bytes;
}
private final double WINDOW_SIZE = 15; // reference 'max'
private final double MAX_CNT = 125000; // 1Mbps in bytes/s.
private final float WINDOW_WEIGHT = 0.55;
LinkedList<pkt> inWindow = new LinkedList<pkt>();
LinkedList<pkt> inNow = new LinkedList<pkt>();
int inTotal = 0;
int windowTotal = 0;
CarnivoreP5 c;
PFont font32;

private final float MAX_BANDWIDTH = 100000000.0; 
private final int BINS = 5;
Date lastTime;

int lastBG[]  = new int[3];

boolean dbConnected = false;


void setup() 
{
  db = new SQLite(this, "hostip.sqlite3"); //open database file!
  if (db.connect()) {
    dbConnected = true;  
  }
  else {
    dbConnected = false; 
  }
  
  mapImage = loadImage("512px-Equirectangular-projection.jpg");
  
  size(WIDTH, HEIGHT);
  background(0x00, 0x55, 0xcc);
  frameRate(10);
  lastBG[0] = 0x00;
  lastBG[1] = 0x55;
  lastBG[2] = 0xcc;
  CarnivoreP5 c = new CarnivoreP5(this);
  c.setShouldSkipUDP(false);
  Log.setDebug(false); // Uncomment this for verbose mode
  //c.setVolumeLimit(4);
  // Use the "Create Font" tool to add a 12 point font to your sketch,
  // then use its name as the parameter to loadFont().
  //font = loadFont("CourierNew-12.vlw");
  //textFont(font);
}

void draw() {
  int bg[] = getBackgroundColorFromTrafficSpeed();
  int r = lastBG[0];
  if (bg[0] > lastBG[0]) {
    r += 8;
  } 
  else if (bg[0] < lastBG[0]) {
    r -= 3; 
  }
  int g = lastBG[1];
  int b = lastBG[2];
  background(r,g,b);
  lastBG[0] = r;
  lastBG[1] = g;
  lastBG[2] = b;
  
  // draw new packets
  for (int i=0; i<newPackets/2; i++) {
    stroke(0xFF, 0xFF, 0xFF);
    int x = int(random(WIDTH-1));
    int y = int(random(HEIGHT-1));
    point(x,y);
  }
  newPackets = newPackets/2;
  stroke(0);  
  if (dbConnected) {
    fill(0x00, 0xFF, 0x00); 
  }
  else {
    fill(0xFF, 0x00, 0x00); 
  }
  ellipse(15, 15, 10, 10);
  
  Iterator<String> countriesIter = countries.iterator();
  int q = 50;
  while (countriesIter.hasNext()) {
    text(countriesIter.next(), 50, q); 
    q = q+20;
  }
  
  Iterator<String> citiesIter = cities.iterator();
  q = 50;
  while (citiesIter.hasNext()) {
    text(citiesIter.next(), 250, q); 
    q = q+20;
  }
  
  // draw map
  
  image(mapImage, mapX, mapY);
  
  // draw pins
//  pin seattle = new pin(mapImage, 47.53, -122.30);
//  pin poughkeepsie = new pin(mapImage, 41.7, -73.93);
  
//  seattle.drawSelf( );
//  poughkeepsie.drawSelf();
}

int[] getBackgroundColorFromTrafficSpeed() {

  int lastSecondBytes = sumList(inNow);
  int lastWindowBytes = sumList(inWindow);
  
  prune();
  
  double logSecondBytes = Math.log10(lastSecondBytes);
//  int logWindowBytes = int(Math.log((double)lastWindowBytes));
  
  double logBandwidth = Math.log(MAX_BANDWIDTH);
  
  float windowFraction = (float)lastSecondBytes/(lastWindowBytes/(float)WINDOW_SIZE);
  double absFraction = (double)logSecondBytes/logBandwidth;
  
  //System.out.println(logBandwidth +" "+ lastSecondBytes+" "+ + logSecondBytes +" "+ absFraction);
  
  if (absFraction > 1) {
    absFraction = 1;   
  }
  int r = int(Math.round(255 * absFraction));
  if (r > 255) {
    r = 255; 
  }
  int toReturn[] = {r, 0x55, 0xcc};
  return toReturn;
}

synchronized void prune() {
  pkt p;
  int i=0;
  // prune old data from last second buffer
  while (inNow.size() > 0) {
    p = inNow.remove();
    if (! (p.time.getTime() + 1000 < new Date().getTime())) {
      inNow.addFirst(p);
      break; 
    }
    else {
      i++;
    }
  }  
  // prune old data from last minute buffer
  while (inWindow.size() > 0) {
    p = inWindow.remove();
    if (! (p.time.getTime() + 1000*WINDOW_SIZE < new Date().getTime())) {
       inWindow.addFirst(p);
       break;
    } 
  } 
  if (i > 0) {
 //   System.out.println(i); 
  }
}
synchronized int sumList(LinkedList<pkt> l) {
  Date nowTime = new Date();
  Iterator<pkt> iter = l.descendingIterator();
  int sum = 0;
  int count = 0;
  while (iter.hasNext()) {
    pkt p = iter.next();
    sum += p.bytes;
    count++;
  }
//  System.out.println(count+" "+sum); 
  return sum;
}

String getCityByIP(IPAddress ip) {
  if (!dbConnected) {
    return null; 
  }

  db.query("SELECT city as \"City\" FROM ip4_"+ip.octet1()+" WHERE b="+ip.octet2()+" AND c="+ip.octet3()+";");
  String city = "NONE";
  while (db.next()) {
    city = db.getString("City"); 
  }
  if (!city.equals("NONE")) {
    db.query("SELECT name as \"Name\" FROM cityByCountry WHERE city="+city);
  }
  String cityName = "NONE";
  while (db.next()) {
    cityName = db.getString("Name");
  }
  return cityName;
}
String getCountryByIP(IPAddress ip) {
  if (!dbConnected) {
    return null; 
  }

  db.query("SELECT country as \"Country\" FROM ip4_"+ip.octet1()+" WHERE b="+ip.octet2()+" AND c="+ip.octet3()+";");
  String country = "NONE";
  while (db.next()) {
    country = db.getString("Country"); 
  }
  if (!country.equals("NONE")) {
    db.query("SELECT name as \"Name\" FROM countries WHERE id="+country);
  }
  String countryName = "NONE";
  while (db.next()) {
    countryName = db.getString("Name");
  }
  return countryName;
  
}

int[] getLatLonByIP(IPAddress ip) {
  if (!dbConnected) {
    return null;
  }
  db.query("SELECT city as \"City\" FROM ip4_"+ip.octet1()+" WHERE b="+ip.octet2()+" AND c="+ip.octet3()+";");
  String city = "NONE";
  while (db.next()) {
    city = db.getString("City"); 
  }
  if (!city.equals("NONE")) {
    db.query("SELECT lat, lng as \"Latitude\", \"Longitude\" FROM cityByCountry WHERE city="+city);
  }
  float lat = 1000;
  float lng = 1000;
  while (db.next()) {
    lat = db.getFloat("Latitude");
    lng = db.getFloat("Longitude"); 
  }
  
  return [lat, lng];
}
// Called each time a new packet arrives
synchronized void packetEvent(CarnivorePacket packet) {
  pkt pkt = new pkt();
  pkt.time = new Date();
  pkt.bytes = packet.data.length;
  
  if (pkt.bytes == 0) {
    return;
  }
  IPAddress ip = packet.receiverAddress;  
  String country = getCountryByIP(ip);
  String city = getCityByIP(ip);
  int[] latlon = getLatLonByIP(ip);

  Pin p;
  if (pins.containsKey(ip)) {
    p = pins.get(packet.receiver); 
  }
  else {
    p = new Pin(mapImage, lat, lon, country, city);
  }
  p.addBytes(pkt.bytes);
  //println(packet.receiverAddress+" maps to "+country);
  
  inWindow.add(pkt);
  inNow.add(pkt);
  
  newPackets++;
  //println("[PDE] packetEvent: " + packet.toString());  
}
