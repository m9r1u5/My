package za.m9r1u5.gadgetprobe;

import android.os.Bundle;
import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {
    @Override
    public void onCreate(Bundle savedInstanceState) {
        registerPlugin(NetScanPlugin.class);
        super.onCreate(savedInstanceState);
    }
}
