namespace MiniWireshark.Models;

public static class PacketListSearch
{
    public static int BinarySearchByNumber(IList<CapturedPacket> packets, int number)
    {
        int low = 0;
        int high = packets.Count - 1;

        while (low <= high)
        {
            int mid = low + (high - low) / 2;
            int current = packets[mid].Number;

            if (current == number)
                return mid;
            
            if (current < number)
                low = mid + 1;
            else
                high = mid - 1;
        }
        return -low;
    }
}