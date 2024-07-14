using ImGuiNET;
using ClickableTransparentOverlay;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Swed32;

namespace CheatMenu
{
    public class Menu : Overlay
    {
        bool itemCostDisabled = false;
        int costToggleAddress = 0x1EF79;
        int moneyAddress = 0x0238048;
        float moneyDisplay;

        [DllImport("kernel32.dll")]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesWritten);

        protected override void Render()
        {
            ImGui.Begin("Zoo Tycoo Cheat Menu");
            ImGui.Checkbox("Make everything free", ref itemCostDisabled);
            ImGui.Text("Money: ");
            ImGui.SameLine();
            ImGui.InputFloat("##money", ref moneyDisplay);
            ImGui.End();
        }

        public void MemoryLogic()
        {
            Swed swed = new Swed("zoo");
            Process process = Process.GetProcessesByName("zoo")[0]; // Assuming there's only one instance of the game

            Console.WriteLine("Process: " + process);
            Console.WriteLine("Base address (hex): 0x{0:X}", process.MainModule.BaseAddress);
            Console.WriteLine("Toggle cost address (hex): 0x{0:X}", (IntPtr)(process.MainModule.BaseAddress + costToggleAddress));

            while (true)
            {
                updateItemCostDisabled(process, itemCostDisabled, costToggleAddress);

                updateMoney(process, swed, moneyAddress);

                Thread.Sleep(1000);
            }
        }

        public void updateMoney(Process process, Swed swed, int moneyAddress)
        {
            IntPtr newMoneyAddress = swed.ReadPointer(process.MainModule.BaseAddress, moneyAddress) + 0xC;

            bool userChangedMoneyDisplay = ImGui.IsAnyItemActive(); // Check for active input and Enter press
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
