using ImGuiNET;
using ClickableTransparentOverlay;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Swed32;

namespace CheatMenu
{

    public class MemoryAddress
    {
        string name;
        int offset;
        float memValue;

        public MemoryAddress(string Name, int Offset)
        {
            name = Name;
            offset = Offset;
        }
        public String Name
        {
            get { return name; }
            set { name = value; }
        }
        public int Offset
        {
            get { return offset; }
            set { offset = value; }
        }
        public float Value
        {
            get { return memValue; }
            set { memValue = value; }
        }
    }

    public class Menu : Overlay
    {

        /* Memory Addresses */
        int costToggleAddress = 0x1EF79;
        int seafloorCaveCapacityAddress = 0x0023ACF4;
        int largeConcreteShelterCapacityAddress = 0x00238040;

        // GameObject Address
        int gameConfigAddress = 0x0238048;
        //MemoryAddress maxAdmissionPriceAddress = new MemoryAddress("maxAdmissionPriceAddress", 0x1168);
        MemoryAddress[] MemoryAddresses =
        {
            new MemoryAddress("buildingUseCostDefaultAddress", 0x1174),
            new MemoryAddress("buildingUseCostMaxAddress", 0x1178),
            new MemoryAddress("zooDooRecyclingAmountAddress", 0x117C),
            new MemoryAddress("minAdmissionPriceAddress", 0x1164),
            new MemoryAddress("maxAdmissionPriceAddress", 0x1168),
    };
        int moneyAddress = 0x0238048;
        //int buildingUseCostDefaultAddress = 0x0238048;
        // int buildingUseCostMaxAddress = 0x0238048;
        // int zooDooRecyclingAmountAddress = 0x0238048;
        //   int maxAdmissionPriceAddress = 0x0238048;
        //int minAdmissionPriceAddress = 0x0238048;

        //int maxTankHeightAddress = 0x1AF3B6;
        int maxTankHeightAddress = 0x023AF18;

        int maxGuestsAddress = 0x00238048; // 4 bytes
        float maxGuests = -1;

        /* ---------------- */

        bool itemCostDisabled = false;
        float moneyDisplay;
        float seafloorCaveCapacity; // This is actually represented as 4 bytes
        float largeConcreteShelterCapacity; // This is actually represented as 4 bytes
        float buildingUseCostDefault;
        float buildingUseCostMax;
        float zooDooRecyclingAmount;
        float maxAdmissionPrice;
        float minAdmissionPrice;
        //float maxTankHeight;

        // Tank values
        private float initialWaterPurity = 100.0f;
        private float tankWaterPurityDecayTime = 24.0f;
        private float tankTerrain = 0.0f;
        private float extremelyMurkyWaterPurity = 0.0f;
        private float saltWater = 35.0f;
        private float wallHeightPriceDivisor = 100.0f;
        private float maxTankHeight = 20.0f;
        private float initialHeightShow = 1.0f;
        private float initialHeight = 5.0f;
        private float initialWaterLevel = 100.0f;
        private float initialSalinity = 35.0f;
        private float initialTemperature = 25.0f;
        private float initialSinkShow = 1.0f;
        private float initialSink = 0.0f;
        private float terrainShow = 1.0f;
        private float freshWater = 0.0f;


        /* Controls */
        private bool waitingForKeyPress = false;
        private string controlToRemap = null;
        private Dictionary<string, ImGuiKey> keyMappings = new Dictionary<string, ImGuiKey>
{
    { "Play", ImGuiKey.Space },
    { "Pause", ImGuiKey.P },
    { "Speed Up", ImGuiKey.RightArrow },
    { "Slow Down", ImGuiKey.LeftArrow }
};

        [DllImport("kernel32.dll")]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("user32.dll")]
        private static extern short GetAsyncKeyState(int vKey);

        protected override void Render()
        {
            // Set up window styling
            ImGui.PushStyleVar(ImGuiStyleVar.WindowRounding, 10.0f);
            ImGui.PushStyleVar(ImGuiStyleVar.FrameRounding, 6.0f);
            ImGui.PushStyleVar(ImGuiStyleVar.WindowPadding, new System.Numerics.Vector2(15, 15));

            // Set color scheme
            var style = ImGui.GetStyle();
            style.Colors[(int)ImGuiCol.WindowBg] = new System.Numerics.Vector4(0.13f, 0.14f, 0.17f, 0.95f);
            style.Colors[(int)ImGuiCol.Header] = new System.Numerics.Vector4(0.24f, 0.27f, 0.32f, 0.75f);
            style.Colors[(int)ImGuiCol.HeaderHovered] = new System.Numerics.Vector4(0.34f, 0.37f, 0.42f, 0.75f);
            style.Colors[(int)ImGuiCol.Button] = new System.Numerics.Vector4(0.24f, 0.27f, 0.32f, 1.0f);
            style.Colors[(int)ImGuiCol.ButtonHovered] = new System.Numerics.Vector4(0.34f, 0.37f, 0.42f, 1.0f);

            // Main window setup
            ImGui.SetNextWindowSize(new System.Numerics.Vector2(500, 600), ImGuiCond.FirstUseEver);
            ImGui.Begin("Zoo Tycoon Cheat Overlay",
                ImGuiWindowFlags.NoCollapse |
                ImGuiWindowFlags.NoScrollbar |
                ImGuiWindowFlags.NoScrollWithMouse |
                ImGuiWindowFlags.NoFocusOnAppearing |
                ImGuiWindowFlags.NoBringToFrontOnFocus); // These don't do anything :(

            RenderHeader();
            ImGui.Spacing();
            ImGui.Separator();
            ImGui.Spacing();

            if (ImGui.BeginTabBar("MainTabs", ImGuiTabBarFlags.None))
            {
                RenderGameConfigTab();
                RenderMoneyTab();
                RenderTanksTab();
                RenderBuildingsTab();
                RenderControlsTab();
                RenderMemoryTab();
                ImGui.EndTabBar();
            }

            RenderStatusBar();

            ImGui.End();
            ImGui.PopStyleVar(3);
        }

        private void RenderHeader()
        {
            ImGui.PushFont(ImGui.GetIO().Fonts.Fonts[0]); // Assuming default font
            ImGui.Text("Zoo Tycoon Trainer");
            ImGui.PopFont();

            ImGui.SameLine(ImGui.GetWindowWidth() - 100);
            if (Process.GetProcessesByName("zoo").Length > 0)
            {
                ImGui.PushStyleColor(ImGuiCol.Text, new System.Numerics.Vector4(0.2f, 0.8f, 0.2f, 1.0f));
                ImGui.Text("Connected");
                ImGui.PopStyleColor();
            }
            else
            {
                ImGui.PushStyleColor(ImGuiCol.Text, new System.Numerics.Vector4(0.8f, 0.2f, 0.2f, 1.0f));
                ImGui.Text("Not Connected");
                ImGui.PopStyleColor();
            }
        }

        private void RenderMoneyTab()
        {
            if (ImGui.BeginTabItem("Money"))
            {
                ImGui.BeginChild("MoneySection", new System.Numerics.Vector2(0, 0), true);

                // Free items toggle with custom styling
                ImGui.PushStyleColor(ImGuiCol.FrameBg, new System.Numerics.Vector4(0.2f, 0.2f, 0.2f, 0.5f));
                ImGui.PushStyleColor(ImGuiCol.FrameBgHovered, new System.Numerics.Vector4(0.3f, 0.3f, 0.3f, 0.5f));
                if (ImGui.Checkbox("Make Everything Free", ref itemCostDisabled))
                {
                    // Your existing logic
                }
                ImGui.PopStyleColor(2);

                ImGui.Spacing();
                RenderValueEditor("Current Money", ref moneyDisplay, "$", 0, 999999999);
                RenderValueEditor("Max Admission Price", ref maxAdmissionPrice, "$", 0, 1000);
                RenderValueEditor("Min Admission Price", ref minAdmissionPrice, "$", 0, 1000);

                ImGui.EndChild();
                ImGui.EndTabItem();
            }
        }

        private void RenderGameConfigTab()
        {
            if (ImGui.BeginTabItem("Game Config"))
            {
                ImGui.BeginChild("GameConfigSection", new System.Numerics.Vector2(0, 0), true);

                RenderValueEditor("Zoo Doo Recycling Amount", ref zooDooRecyclingAmount, "%", 0, 100);
                RenderValueEditor("Building Use Cost Max", ref buildingUseCostMax, "$", 0, 100);
                RenderValueEditor("Building Use Cost Default", ref buildingUseCostDefault, "$", 0, 100);
                RenderValueEditor("Max guests", ref maxGuests, "guests", 0, 10000);

                ImGui.EndChild();
                ImGui.EndTabItem();
            }
        }

        private void RenderBuildingsTab()
        {
            if (ImGui.BeginTabItem("Buildings"))
            {
                ImGui.BeginChild("BuildingsSection", new System.Numerics.Vector2(0, 0), true);

                if (ImGui.CollapsingHeader("Shelter Capacities", ImGuiTreeNodeFlags.DefaultOpen))
                {
                    RenderValueEditor("Seafloor Cave", ref seafloorCaveCapacity, "animals", 0, 100);
                    RenderValueEditor("Large Concrete Shelter", ref largeConcreteShelterCapacity, "animals", 0, 100);
                }


                ImGui.EndChild();
                ImGui.EndTabItem();
            }
        }

        private void RenderControlsTab()
        {
            if (ImGui.BeginTabItem("Controls"))
            {
                ImGui.BeginChild("ControlsSection", new System.Numerics.Vector2(0, 0), true);

                foreach (var mapping in keyMappings)
                {
                    ImGui.Text($"{mapping.Key}:");
                    ImGui.SameLine(150);

                    if (ImGui.Button($"{mapping.Value}##{mapping.Key}"))
                    {
                        waitingForKeyPress = true;
                        controlToRemap = mapping.Key;
                    }

                    if (waitingForKeyPress && controlToRemap == mapping.Key)
                    {
                        ImGui.SameLine();
                        ImGui.TextColored(new System.Numerics.Vector4(1, 1, 0, 1), "Press any key...");
                        HandleKeyRemapping(mapping.Key);
                    }
                }

                ImGui.EndChild();
                ImGui.EndTabItem();
            }
        }

        private void RenderTanksTab()
        {
            if (ImGui.BeginTabItem("Tanks"))
            {
                ImGui.BeginChild("TanksSection", new System.Numerics.Vector2(0, 0), true);

                RenderValueEditor("Initial Water Purity", ref initialWaterPurity, "%", 0, 100);
                RenderValueEditor("Tank Water Purity Decay Time", ref tankWaterPurityDecayTime, "hours", 0, 168);
                RenderValueEditor("Tank Terrain", ref tankTerrain, "level", 0, 10);
                RenderValueEditor("Extremely Murky Water Purity", ref extremelyMurkyWaterPurity, "%", 0, 100);
                RenderValueEditor("Salt Water", ref saltWater, "ppt", 0, 50);
                RenderValueEditor("Wall Height Price Divisor", ref wallHeightPriceDivisor, "factor", 1, 1000);
                RenderValueEditor("Maximum Tank Height", ref maxTankHeight, "m", 0, 100);
                RenderValueEditor("Initial Height Show", ref initialHeightShow, "bool", 0, 1);
                RenderValueEditor("Initial Height", ref initialHeight, "m", 0, 50);
                RenderValueEditor("Initial Water Level", ref initialWaterLevel, "%", 0, 100);
                RenderValueEditor("Initial Salinity", ref initialSalinity, "ppt", 0, 50);
                RenderValueEditor("Initial Temperature", ref initialTemperature, "°C", 0, 40);
                RenderValueEditor("Initial Sink Show", ref initialSinkShow, "bool", 0, 1);
                RenderValueEditor("Initial Sink", ref initialSink, "level", 0, 10);
                RenderValueEditor("Terrain Show", ref terrainShow, "bool", 0, 1);
                RenderValueEditor("Fresh Water", ref freshWater, "ppt", 0, 5);

                ImGui.EndChild();
                ImGui.EndTabItem();
            }
        }

        private void RenderMemoryTab()
        {
            if (ImGui.BeginTabItem("Memory"))
            {
                ImGui.BeginChild("MemorySection", new System.Numerics.Vector2(0, 0), true);



                ImGui.EndChild();
                ImGui.EndTabItem();
            }
        }

        private void RenderValueEditor(string label, ref float value, string unit, float min, float max)
        {
            ImGui.PushID(label);

            ImGui.BeginGroup();
            ImGui.Text(label);

            ImGui.SetNextItemWidth(ImGui.GetWindowWidth() * 0.6f);
            if (ImGui.SliderFloat("##slider", ref value, min, max, $"{value:F1} {unit}"))
            {
                // Your value update logic here
            }

            ImGui.SameLine();
            ImGui.SetNextItemWidth(ImGui.GetWindowWidth() * 0.2f);
            if (ImGui.InputFloat("##input", ref value, 0, 0, "%.1f"))
            {
                value = Math.Clamp(value, min, max);
                // Your value update logic here
            }

            ImGui.EndGroup();

            ImGui.PopID();
        }

        private void RenderStatusBar()
        {
            ImGui.Separator();
            ImGui.SetCursorPosY(ImGui.GetWindowHeight() - 30);

            // Display last action or status
            ImGui.Text("Status: ");
            ImGui.SameLine();
            ImGui.TextColored(new System.Numerics.Vector4(0.7f, 0.7f, 0.7f, 1.0f), "Ready");

            // Version info
            ImGui.SameLine(ImGui.GetWindowWidth() - 100);
            ImGui.TextDisabled("v1.0.0");
        }

        private void HandleKeyRemapping(string control)
        {
            ImGuiIOPtr io = ImGui.GetIO();
            for (int key = 0; key < (int)ImGuiKey.COUNT; key++)
            {
                if (io.KeysDown[key])
                {
                    SetKeyMapping(control, (ImGuiKey)key);
                    waitingForKeyPress = false;
                    controlToRemap = null;
                    break;
                }
            }
        }

        private string GetKeyMapping(string control)
        {
            // Implement this method to return the current key mapping for the control
            // This should access your key mapping storage (e.g., a Dictionary<string, ImGuiKey>)
            // Return the key as a string (e.g., "Spacebar", "A", "Left Arrow", etc.)
            if (keyMappings.TryGetValue(control, out ImGuiKey key))
            {
                return key.ToString();
            }
            return "Unmapped";
        }
        private void SetKeyMapping(string control, ImGuiKey key)
        {
            // Updates key mapping storage
            if (keyMappings.ContainsKey(control))
            {
                keyMappings[control] = key;
            }
            else
            {
                keyMappings.Add(control, key);
            }
        }
        private int ConvertImGuiKeyToVK(ImGuiKey key)
        {
            // This is a basic conversion. You might need to expand this for all keys you use.
            switch (key)
            {
                case ImGuiKey.Space: return 0x20;
                case ImGuiKey.P: return 0x50;
                case ImGuiKey.LeftArrow: return 0x25;
                case ImGuiKey.RightArrow: return 0x27;
                case ImGuiKey.Enter: return 0x0D;
                // Add more cases as needed
                default: return 0;
            }
        }
        private bool IsKeyPressed(ImGuiKey key)
        {
            // Convert ImGuiKey to Windows virtual key code
            int vkCode = ConvertImGuiKeyToVK(key);

            // Check if the key is pressed
            return (GetAsyncKeyState(vkCode) & 0x8000) != 0;
        }
        private void CheckKeyPresses()
        {
            foreach (var mapping in keyMappings)
            {
                if (IsKeyPressed(mapping.Value))
                {
                    switch (mapping.Key)
                    {
                        case "Play":
                            Play();
                            break;
                    }
                }
            }
        }

        private void Play()
        {
            Console.WriteLine("Play action triggered");
            // Add your play logic here
        }

        public void MemoryLogic()
        {
            Process[] zooProcessArray = Process.GetProcessesByName("zoo");
            if (zooProcessArray.Length == 0)
            {
                Console.WriteLine("Game not found. Please make sure you are running Zoo Tycoon and restart");
                return;
            }
            Process process = zooProcessArray[0]; // Assuming there's only one instance of the game
            Swed swed = new Swed("zoo");

            Console.WriteLine("Process: " + process);
            Console.WriteLine("Base address (hex): 0x{0:X}", process.MainModule.BaseAddress);
            Console.WriteLine("Toggle cost address (hex): 0x{0:X}", (IntPtr)(process.MainModule.BaseAddress + costToggleAddress));

            while (true)
            {

                // TEST
                // var readBuffer = new byte[4];
                // IntPtr bytesRead;
                // ReadProcessMemory(process.Handle, (IntPtr)(process.MainModule.BaseAddress + 0x00b4d0e), readBuffer , 4, out bytesRead);
                // Console.WriteLine("Base address:  " + readBuffer[0] + " " + readBuffer[1] + " " + readBuffer[2] + " " + readBuffer[3]);

                updateItemCostDisabled(process, itemCostDisabled, costToggleAddress);

                updateMoney(process, swed, moneyAddress);

                // ! Not working !
                updateShelters(process, swed, seafloorCaveCapacityAddress, largeConcreteShelterCapacityAddress);

                // Game Config
                foreach (MemoryAddress memAddress in MemoryAddresses)
                {
                    updateGameConfig(process, swed, memAddress);
                }
                //updateGameConfig(process, swed, maxAdmissionPriceAddress);

                updateMaxGuests(process, swed, maxGuestsAddress);

                //updateBuildingUseCostDefault(process, swed);
                //updateBuildingUseCostMax(process, swed);
                //updateZooDooRecylcingAmount(process, swed);
                //updateMaxAdmissionPrice(process, swed, maxAdmissionPriceAddress);
                //updateMinAdmissionPrice(process, swed, minAdmissionPriceAddress);

                updateMaxTankHeight(process, maxTankHeightAddress);

                // For updated mappings
                // TODO: Find permanent mappings so we don't have to check and manually do this :(
                CheckKeyPresses();

                Thread.Sleep(100);
            }
        }

        public void updateMaxTankHeight(Process process, int maxTankHeightAddress)
        {

            //IntPtr newMaxTankHeightAddress = swed.ReadPointer(process.MainModule.BaseAddress, maxTankHeightAddress) + 0x1168;
            IntPtr bytesRead;
            //ReadProcessMemory(process.Handle, (IntPtr)(process.MainModule.BaseAddress + maxTankHeightAddress), readBuffer, 2, out bytesRead);

            //Console.WriteLine(": 0x{0:X}", (IntPtr)(process.MainModule.BaseAddress + maxTankHeightAddress));
            bool userChangedMoneyDisplay = ImGui.IsAnyItemActive(); //  && IsKeyPressed(ImGuiKey.Enter); // Check for active input and Enter press
            if (userChangedMoneyDisplay)
            {

                //byte[] buffer = new byte[5];
                //byte[] convertedInput = BitConverter.GetBytes((uint)maxTankHeight);
                //buffer[0] = 0xB8;
                //buffer[1] = convertedInput[0];
                //buffer[2] = convertedInput[1];
                //buffer[3] = convertedInput[2];
                //buffer[4] = convertedInput[3];
                //Console.WriteLine(maxTankHeight);
                //Console.WriteLine(BitConverter.GetBytes((uint)maxTankHeight)[0]);
                byte[] buffer = { (byte)maxTankHeight };

                WriteProcessMemory(process.Handle, (IntPtr)(process.MainModule.BaseAddress + maxTankHeightAddress), buffer, 1, out bytesRead);
            }
            else
            {
                var readBuffer = new byte[1];
                ReadProcessMemory(process.Handle, (IntPtr)(process.MainModule.BaseAddress + maxTankHeightAddress), readBuffer, 1, out bytesRead);
                //Console.WriteLine(readBuffer[1] + ((uint)readBuffer[2] << 8) + ((uint)readBuffer[3] << 16) + ((uint)readBuffer[4] << 24));
                //Console.WriteLine("Base address: " + readBuffer[0]);// + " " + readBuffer[1] + " " + readBuffer[2] + " " + readBuffer[3] + " " + readBuffer[4]);
                maxTankHeight = readBuffer[0];
            }
        }


        public void updateGameConfig(Process process, Swed swed, MemoryAddress memAddress)
        {
            IntPtr gameAttrAddress = swed.ReadPointer(process.MainModule.BaseAddress, gameConfigAddress) + memAddress.Offset;
            // Console.WriteLine("Money address (hex): 0x{0:X}", newMinAdmissionPriceAddress);

            bool userChangedMoneyDisplay = ImGui.IsAnyItemActive(); //  && IsKeyPressed(ImGuiKey.Enter); // Check for active input and Enter press
            if (userChangedMoneyDisplay)
            {
                Console.WriteLine($"Changed {memAddress.Name}");
                switch (memAddress.Name)
                {
                    case "maxAdmissionPriceAddress":
                        swed.WriteFloat(gameAttrAddress, maxAdmissionPrice);
                        break;
                    case "minAdmissionPriceAddress":
                        swed.WriteFloat(gameAttrAddress, minAdmissionPrice);
                        break;

                    case "zooDooRecyclingAmountAddress":
                        swed.WriteFloat(gameAttrAddress, zooDooRecyclingAmount);
                        break;
                    case "buildingUseCostMaxAddress":
                        swed.WriteFloat(gameAttrAddress, buildingUseCostMax);
                        break;
                    case "buildingUseCostDefaultAddress":
                        swed.WriteFloat(gameAttrAddress, buildingUseCostDefault);
                        break;
                    default:
                        Console.WriteLine("Error: No attribute found");
                        break;
                }
                //swed.WriteFloat(gameAttrAddress, maxAdmissionPrice);
            }
            else
            {
                memAddress.Value = swed.ReadFloat(gameAttrAddress);

                switch (memAddress.Name)
                {
                    case "maxAdmissionPriceAddress":
                        //Console.WriteLine($"TTTTTChanged {memAddress.Name} to: {memAddress.Value}");
                        maxAdmissionPrice = memAddress.Value;
                        break;
                    case "minAdmissionPriceAddress":
                        minAdmissionPrice = memAddress.Value;
                        break;
                    case "zooDooRecyclingAmountAddress":
                        zooDooRecyclingAmount = memAddress.Value;
                        break;
                    case "buildingUseCostMaxAddress":
                        buildingUseCostMax = memAddress.Value;
                        break;
                    case "buildingUseCostDefaultAddress":
                        buildingUseCostDefault = memAddress.Value;
                        break;
                    default:
                        Console.WriteLine("Error: No attribute found");
                        break;
                }
            }
        }


        private void updateShelters(Process process, Swed swed, int shelterAddress, int largeConcreteShelterCapacityAddress)
        {
            IntPtr newShelterAddress = swed.ReadPointer(process.MainModule.BaseAddress, shelterAddress) + 0x2F914;
            IntPtr lcsAddress = swed.ReadPointer(process.MainModule.BaseAddress, largeConcreteShelterCapacityAddress);
            //lcsAddress = swed.ReadPointer(lcsAddress + 0x98);
            //lcsAddress = swed.ReadPointer(lcsAddress + 0x2A4);
            //lcsAddress = swed.ReadPointer(lcsAddress + 0x3F0);

            //Console.WriteLine("Shelter address (hex): 0x{0:X}", newShelterAddress);
            //Console.WriteLine("Shelter address (hex): 0x{0:X}", lcsAddress);

            bool userChangedShelterInput = ImGui.IsAnyItemActive(); ; //  && IsKeyPressed(ImGuiKey.Enter); // Check for active input and Enter press
            if (userChangedShelterInput)
            {
                byte[] sfcCapacity = { (byte)seafloorCaveCapacity };
                byte[] lcsCapacity = { (byte)largeConcreteShelterCapacity };
                //capacity[0] = (byte)seafloorCaveCapacity;
                //Console.WriteLine($"Changed capacity to: {sfcCapacity[0]}. Original: {largeConcreteShelterCapacity}");

                swed.WriteBytes(newShelterAddress, sfcCapacity);
                swed.WriteBytes(lcsAddress, lcsCapacity);
            }
            else
            {
                byte[] buffer = swed.ReadBytes(newShelterAddress, 1);
                byte[] lcsCapacity = swed.ReadBytes(lcsAddress, 1);
                seafloorCaveCapacity = buffer[0];
                largeConcreteShelterCapacity = lcsCapacity[0];
                Console.WriteLine("Shelter Data: " + lcsCapacity[0]);
                Console.WriteLine("POINTER: " + swed.ReadFloat(lcsAddress));

            }
        }

        public void updateMoney(Process process, Swed swed, int moneyAddress)
        {
            IntPtr newMoneyAddress = swed.ReadPointer(process.MainModule.BaseAddress, moneyAddress) + 0xC;
            // Console.WriteLine("Money address (hex): 0x{0:X}", newMoneyAddress);

            bool userChangedMoneyDisplay = ImGui.IsAnyItemActive(); ; //  && IsKeyPressed(ImGuiKey.Enter); // Check for active input and Enter press
            if (userChangedMoneyDisplay)
            {
                Console.WriteLine($"Changed money to: {moneyDisplay}");
                swed.WriteFloat(newMoneyAddress, moneyDisplay);
            }
            else
            {
                moneyDisplay = swed.ReadFloat(newMoneyAddress);
            }
        }

        public void updateMaxGuests(Process process, Swed swed, int maxGuestsAddress)
        {
            IntPtr newMaxGuestsAddress = swed.ReadPointer(process.MainModule.BaseAddress, maxGuestsAddress) + 0x78;

           bool userChangedDisplay = ImGui.IsAnyItemActive(); ; //  && IsKeyPressed(ImGuiKey.Enter); // Check for active input and Enter press
            if (userChangedDisplay)
           {
                int intValue = (int)Math.Floor(maxGuests);
                byte[] maxGuestByte = BitConverter.GetBytes(intValue);
                swed.WriteBytes(newMaxGuestsAddress, maxGuestByte);
            }
            else
           {
                byte[] buffer = swed.ReadBytes(newMaxGuestsAddress, 4);
                maxGuests = BitConverter.ToInt32(buffer, 0);
           }

         
        }

        public static void updateItemCostDisabled(Process process, bool itemCostDisabled, int costToggleAddress)
        {
            byte[] buffer = new byte[2];

            if (itemCostDisabled)
            {
                buffer[0] = 0x90;
                buffer[1] = 0x90;
            }
            else
            {
                buffer[0] = 0xD9;
                buffer[1] = 0x19;
            }

            IntPtr bytesRead;
            var readBuffer = new byte[2];
            ReadProcessMemory(process.Handle, (IntPtr)(process.MainModule.BaseAddress + costToggleAddress), readBuffer, 2, out bytesRead);
            bool success = WriteProcessMemory(process.Handle, (IntPtr)(process.MainModule.BaseAddress + costToggleAddress), buffer, 2, out bytesRead);
            ReadProcessMemory(process.Handle, (IntPtr)(process.MainModule.BaseAddress + costToggleAddress), buffer, 2, out bytesRead);

            //Console.WriteLine("Base address: " + readBuffer[0] + " " + readBuffer[1]);
        }


        public static void Main(string[] args)
        {
            Console.WriteLine("Starting menu...");

            Menu menu = new Menu();
            menu.Start().Wait();
            Thread menuThread = new Thread(menu.MemoryLogic) { IsBackground = true };
            menuThread.Start();
        }
    }
}
