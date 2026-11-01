package za.m9r1u5.gadgetprobe;

import android.Manifest;
import android.content.Context;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.RouteInfo;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiManager;

import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import com.getcapacitor.JSArray;
import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.FileReader;
import java.io.InputStream;
import java.net.ConnectException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.HttpURLConnection;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/** Local-network tools for finding and identifying Wi-Fi gadgets. */
@CapacitorPlugin(name = "NetScan")
public class NetScanPlugin extends Plugin {

    private static final int[] QUICK_PORTS = {80, 6668, 443};
    private static final int[] PORTS = {80, 443, 6668, 6053, 1883, 554, 8080, 8008, 8009, 8888, 9999, 49153, 5000, 7000, 62078, 23, 22, 53};
    private volatile boolean cancel = false;

    private ConnectivityManager cm() {
        return (ConnectivityManager) getContext().getSystemService(Context.CONNECTIVITY_SERVICE);
    }

    /** The Wi-Fi network specifically, so a VPN doesn't swallow local traffic. */
    private Network findWifi(ConnectivityManager cm) {
        for (Network n : cm.getAllNetworks()) {
            NetworkCapabilities nc = cm.getNetworkCapabilities(n);
            if (nc != null && nc.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) && !nc.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return n;
        }
        return null;
    }

    private boolean vpnOn(ConnectivityManager cm) {
        for (Network n : cm.getAllNetworks()) {
            NetworkCapabilities nc = cm.getNetworkCapabilities(n);
            if (nc != null && nc.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return true;
        }
        return false;
    }

    private JSObject netInfo(ConnectivityManager cm, Network wifi) {
        JSObject r = new JSObject();
        r.put("vpn", vpnOn(cm));
        r.put("wifi", wifi != null);
        if (wifi == null) return r;
        LinkProperties lp = cm.getLinkProperties(wifi);
        if (lp == null) return r;
        for (LinkAddress la : lp.getLinkAddresses()) {
            if (la.getAddress() instanceof Inet4Address) {
                r.put("ip", la.getAddress().getHostAddress());
                r.put("prefix", la.getPrefixLength());
            }
        }
        for (RouteInfo ri : lp.getRoutes()) {
            if (ri.isDefaultRoute() && ri.getGateway() instanceof Inet4Address) r.put("gateway", ri.getGateway().getHostAddress());
        }
        return r;
    }

    @PluginMethod
    public void info(PluginCall call) {
        ConnectivityManager cm = cm();
        call.resolve(netInfo(cm, findWifi(cm)));
    }

    @PluginMethod
    public void stop(PluginCall call) {
        cancel = true;
        call.resolve();
    }

    private static int toInt(InetAddress a) {
        byte[] b = a.getAddress();
        return ((b[0] & 0xff) << 24) | ((b[1] & 0xff) << 16) | ((b[2] & 0xff) << 8) | (b[3] & 0xff);
    }

    private static InetAddress toInet(int h) throws Exception {
        return InetAddress.getByAddress(new byte[]{(byte) (h >>> 24), (byte) (h >>> 16), (byte) (h >>> 8), (byte) h});
    }

    /** Returns -1 closed/no answer, 0 refused (host alive), 1 open. */
    private int tryPort(InetAddress a, int port, int timeout) {
        Socket s = new Socket();
        try {
            s.connect(new InetSocketAddress(a, port), timeout);
            return 1;
        } catch (ConnectException ce) {
            String m = String.valueOf(ce.getMessage()).toLowerCase();
            return m.contains("refused") ? 0 : -1;
        } catch (Exception e) {
            return -1;
        } finally {
            try { s.close(); } catch (Exception ignored) { }
        }
    }

    private JSObject probe(int h, int self, int timeout) {
        if (cancel) return null;
        try {
            InetAddress a = toInet(h);
            boolean alive = false;
            try { alive = a.isReachable(timeout); } catch (Exception ignored) { }
            JSArray open = new JSArray();
            Set<Integer> tried = new HashSet<>();
            if (!alive) {
                for (int p : QUICK_PORTS) {
                    if (cancel) return null;
                    int r = tryPort(a, p, 220);
                    tried.add(p);
                    if (r >= 0) alive = true;
                    if (r == 1) open.put(p);
                }
            }
            if (!alive) return null;
            for (int p : PORTS) {
                if (cancel) break;
                if (tried.contains(p)) continue;
                if (tryPort(a, p, timeout) == 1) open.put(p);
            }
            JSObject o = new JSObject();
            o.put("ip", a.getHostAddress());
            o.put("ports", open);
            o.put("self", h == self);
            try {
                String name = a.getCanonicalHostName();
                if (name != null && !name.equals(a.getHostAddress())) o.put("name", name);
            } catch (Exception ignored) { }
            return o;
        } catch (Exception e) {
            return null;
        }
    }

    private Map<String, String> readArp() {
        Map<String, String> m = new HashMap<>();
        try (BufferedReader br = new BufferedReader(new FileReader("/proc/net/arp"))) {
            String line = br.readLine();
            while ((line = br.readLine()) != null) {
                String[] f = line.trim().split("\\s+");
                if (f.length >= 4 && !f[3].equals("00:00:00:00:00:00")) m.put(f[0], f[3]);
            }
        } catch (Exception ignored) { }
        return m;
    }

    @PluginMethod
    public void scan(final PluginCall call) {
        cancel = false;
        final int timeout = call.getInt("timeout", 400);
        new Thread(() -> {
            ConnectivityManager cm = cm();
            Network wifi = findWifi(cm);
            if (wifi == null) { call.reject("Phone is not connected to Wi-Fi"); return; }
            cm.bindProcessToNetwork(wifi);
            ExecutorService ex = Executors.newFixedThreadPool(48);
            try {
                JSObject info = netInfo(cm, wifi);
                String ipStr = info.getString("ip");
                if (ipStr == null) { call.reject("No Wi-Fi IPv4 address"); return; }
                int self = toInt(InetAddress.getByName(ipStr));
                int prefix = info.getInteger("prefix", 24);
                int pre = Math.max(prefix, 24);
                int mask = (int) (0xffffffffL << (32 - pre));
                int net = self & mask;
                int count = (1 << (32 - pre)) - 2;
                List<Future<JSObject>> fs = new ArrayList<>();
                for (int i = 1; i <= count; i++) {
                    final int h = net + i;
                    fs.add(ex.submit(() -> probe(h, self, timeout)));
                }
                JSArray found = new JSArray();
                List<JSObject> list = new ArrayList<>();
                int done = 0;
                for (Future<JSObject> f : fs) {
                    if (cancel) break;
                    JSObject o = f.get();
                    done++;
                    if (o != null) list.add(o);
                    if (done % 8 == 0 || done == count) {
                        JSObject p = new JSObject();
                        p.put("done", done);
                        p.put("total", count);
                        p.put("found", list.size());
                        notifyListeners("progress", p);
                    }
                }
                Map<String, String> arp = readArp();
                for (JSObject o : list) {
                    String mac = arp.get(o.getString("ip"));
                    if (mac != null) o.put("mac", mac);
                    found.put(o);
                }
                info.put("devices", found);
                info.put("cancelled", cancel);
                call.resolve(info);
            } catch (Exception e) {
                call.reject("Scan failed: " + e);
            } finally {
                ex.shutdownNow();
                cm.bindProcessToNetwork(null);
            }
        }).start();
    }

    private static String hex(byte[] d, int max) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < d.length && i < max; i++) sb.append(String.format("%02X ", d[i] & 0xff));
        if (d.length > max) sb.append("…");
        return sb.toString().trim();
    }

    private static boolean looksText(byte[] d) {
        int ok = 0;
        for (byte b : d) if ((b >= 32 && b < 127) || b == '\n' || b == '\r' || b == '\t') ok++;
        return d.length > 0 && ok > d.length * 0.9;
    }

    /** Tuya devices broadcast their ID/IP on UDP 6666 (plain) or 6667 (AES with a public key). */
    private static String tuyaDecode(byte[] d) {
        try {
            if (d.length < 24 || !(d[0] == 0 && d[1] == 0 && (d[2] & 0xff) == 0x55 && (d[3] & 0xff) == 0xaa)) {
                return looksText(d) ? new String(d, "UTF-8") : null;
            }
            int len = ((d[12] & 0xff) << 24) | ((d[13] & 0xff) << 16) | ((d[14] & 0xff) << 8) | (d[15] & 0xff);
            int end = Math.min(16 + len - 8, d.length - 8);
            byte[] key = MessageDigest.getInstance("MD5").digest("yGAdlopoPVldABfn".getBytes("UTF-8"));
            for (int off : new int[]{4, 0}) {
                if (16 + off >= end) continue;
                byte[] payload = Arrays.copyOfRange(d, 16 + off, end);
                if (payload[0] == '{') return new String(payload, "UTF-8");
                if (payload.length % 16 != 0) continue;
                try {
                    Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
                    c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"));
                    String s = new String(c.doFinal(payload), "UTF-8");
                    if (s.contains("{")) return s.substring(s.indexOf('{'));
                } catch (Exception ignored) { }
            }
        } catch (Exception ignored) { }
        return null;
    }

    @PluginMethod
    public void listen(final PluginCall call) {
        cancel = false;
        final int seconds = call.getInt("seconds", 15);
        new Thread(() -> {
            ConnectivityManager cm = cm();
            Network wifi = findWifi(cm);
            if (wifi == null) { call.reject("Phone is not connected to Wi-Fi"); return; }
            cm.bindProcessToNetwork(wifi);
            WifiManager wm = (WifiManager) getContext().getApplicationContext().getSystemService(Context.WIFI_SERVICE);
            WifiManager.MulticastLock lock = wm.createMulticastLock("gadgetprobe");
            lock.setReferenceCounted(false);
            lock.acquire();
            List<DatagramSocket> socks = new ArrayList<>();
            DatagramSocket ssdp = null;
            try {
                for (int p : new int[]{6666, 6667, 7000}) {
                    try {
                        DatagramSocket ds = new DatagramSocket(null);
                        ds.setReuseAddress(true);
                        ds.setBroadcast(true);
                        ds.bind(new InetSocketAddress(p));
                        ds.setSoTimeout(250);
                        socks.add(ds);
                    } catch (Exception ignored) { }
                }
                ssdp = new DatagramSocket();
                ssdp.setSoTimeout(250);
                socks.add(ssdp);
                byte[] ms = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n").getBytes("UTF-8");
                InetAddress grp = InetAddress.getByName("239.255.255.250");
                ssdp.send(new DatagramPacket(ms, ms.length, grp, 1900));
                long end = System.currentTimeMillis() + seconds * 1000L;
                long resend = System.currentTimeMillis() + 4000;
                Set<String> seen = new HashSet<>();
                JSArray out = new JSArray();
                byte[] buf = new byte[8192];
                while (System.currentTimeMillis() < end && !cancel) {
                    if (System.currentTimeMillis() > resend) { ssdp.send(new DatagramPacket(ms, ms.length, grp, 1900)); resend = Long.MAX_VALUE; }
                    for (DatagramSocket ds : socks) {
                        try {
                            DatagramPacket pk = new DatagramPacket(buf, buf.length);
                            ds.receive(pk);
                            byte[] data = Arrays.copyOf(pk.getData(), pk.getLength());
                            JSObject o = new JSObject();
                            String from = pk.getAddress().getHostAddress();
                            o.put("ip", from);
                            if (ds == ssdp) {
                                o.put("kind", "ssdp");
                                o.put("port", 1900);
                                o.put("text", new String(data, "UTF-8"));
                            } else {
                                o.put("kind", "broadcast");
                                o.put("port", ds.getLocalPort());
                                o.put("hex", hex(data, 48));
                                String t = tuyaDecode(data);
                                if (t != null) o.put("text", t);
                            }
                            String k = from + "|" + o.getString("kind") + "|" + (o.has("text") ? o.getString("text") : o.getString("hex"));
                            if (seen.add(k)) { out.put(o); notifyListeners("packet", o); }
                        } catch (SocketTimeoutException ignored) {
                        } catch (Exception ignored) { }
                    }
                }
                JSObject r = new JSObject();
                r.put("packets", out);
                call.resolve(r);
            } catch (Exception e) {
                call.reject("Listen failed: " + e);
            } finally {
                for (DatagramSocket ds : socks) ds.close();
                lock.release();
                cm.bindProcessToNetwork(null);
            }
        }).start();
    }

    @PluginMethod
    public void http(final PluginCall call) {
        final String url = call.getString("url");
        if (url == null) { call.reject("No URL"); return; }
        new Thread(() -> {
            HttpURLConnection c = null;
            try {
                ConnectivityManager cm = cm();
                Network wifi = findWifi(cm);
                URL u = new URL(url);
                c = (HttpURLConnection) (wifi != null ? wifi.openConnection(u) : u.openConnection());
                c.setConnectTimeout(3000);
                c.setReadTimeout(5000);
                int code = c.getResponseCode();
                InputStream is = code >= 400 ? c.getErrorStream() : c.getInputStream();
                String body = "";
                if (is != null) {
                    ByteArrayOutputStream bo = new ByteArrayOutputStream();
                    byte[] b = new byte[4096];
                    int n;
                    while ((n = is.read(b)) > 0 && bo.size() < 30000) bo.write(b, 0, n);
                    body = bo.toString("UTF-8");
                }
                JSObject r = new JSObject();
                r.put("status", code);
                r.put("server", c.getHeaderField("Server"));
                r.put("type", c.getContentType());
                r.put("body", body);
                call.resolve(r);
            } catch (Exception e) {
                call.reject(e.toString());
            } finally {
                if (c != null) c.disconnect();
            }
        }).start();
    }

    @PluginMethod
    public void wifiList(PluginCall call) {
        if (ContextCompat.checkSelfPermission(getContext(), Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(getActivity(), new String[]{Manifest.permission.ACCESS_FINE_LOCATION}, 4711);
            call.reject("PERMISSION");
            return;
        }
        try {
            WifiManager wm = (WifiManager) getContext().getApplicationContext().getSystemService(Context.WIFI_SERVICE);
            try { wm.startScan(); } catch (Exception ignored) { }
            JSArray out = new JSArray();
            for (ScanResult r : wm.getScanResults()) {
                JSObject o = new JSObject();
                o.put("ssid", r.SSID);
                o.put("bssid", r.BSSID);
                o.put("level", r.level);
                o.put("freq", r.frequency);
                o.put("open", r.capabilities == null || !(r.capabilities.contains("WPA") || r.capabilities.contains("WEP") || r.capabilities.contains("SAE")));
                out.put(o);
            }
            JSObject res = new JSObject();
            res.put("networks", out);
            call.resolve(res);
        } catch (Exception e) {
            call.reject(e.toString());
        }
    }
}
