# Cisco-Nexus-TCAM-usage-calculator
Calculator that estimates how much TCAM entries will be consumed by your ACL

Recently I had a migration from a pair of good old Catalysts 6500 to VxLAN fabric of Nexus 92160 switches and while Catalysts seems to have some unbelieveable infinite TCAM space that was enough for 10 years of adding more and more of new VLANS and ACLs, Nexus' TCAM was exhausted faster than I pronounced T in TCAM (yeah, I'd like to put Doge and Cheems meme here). This is how I came witn this cheap and cheerful script.

This script would be impossible without this article - https://www.pants.org/2017/02/qos-on-the-nexus-9k-estimating-tcam-usage-part-1/ - which decribes the logic behind TCAM calculation. If you're curious about how calculations are made, I suggest reading this.

## What Does It Do
- deletes overlapping entries in your ACL if it has such - for both ports and subnets. This is important thing to do as many massive ACLs tend to have overlapping entries. Such entries are optimized when programming to TCAM so it's necessary to do the same while calculating TCAM usage
- counts how much TCAM will be consumed expanding port ranges
- LOU usage and fragmented entries (see more about fragmented entries here - https://www.cisco.com/c/en/us/support/docs/ip/generic-routing-encapsulation-gre/8014-acl-wp.html) are included in calculations

## What It Doesn't Do

One thing implemented in TCAM and not included in this script is wildcard calculations. On a real hardware you'll see wildcard masks used like this:

ACL entries:

        1340 permit ip any 10.54.123.88/32
        1350 permit ip any 10.54.123.72/32

These two entries combined to one with wildcard mask:

        [0x00ce:0x00da:0x00da] permit ip 0.0.0.0/0 10.54.123.72/255.255.255.239   routeable 0x1  [0]

So in case you're one of these mythical persons from interview questions who filter traffic basing on odd/even hosts/subnets, this script is not for you. For all the other cases where having these wildcard entries is more or less of a chance, this script will always show a bit more TCAM consumed than it would be on a real hardware - larger error for larger ACL. This script was tested on several ACLs, for a relatively small ACLs consuming 100 TCAM entries the error rate was ~5%. For the largest ACL of 800 TCAM entries error rate was about 10%.

## Examples

        10 permit tcp 192.168.1.4/30 range 1 4 0.0.0.0/0 range 1 4
        20 permit tcp 192.168.1.16/28 range 1 4 0.0.0.0/0 range 1 4
        30 permit tcp 0.0.0.0/0 range 1 4 192.168.1.4/30 range 1 4
        40 permit tcp 0.0.0.0/0 range 1 4 192.168.1.16/28 range 1 4
        50 permit tcp 0.0.0.0/0 192.168.1.42/32
        60 permit udp 192.168.0.0/32 range 1111 2222 10.0.0.0/8
        70 permit udp 192.168.0.1/32 range 1111 2222 10.0.0.0/8		
        80 permit udp 192.168.0.1/32 range 3333 4444 10.0.0.0/8

Running script for this ACL will show the following:
>>>

We are now replacing this line  
        permit udp 192.168.0.0/32 ports 1111 2222 10.0.0.0/8 ports 0 0  
because it overlaps with this line:  
        permit udp 192.168.0.1/32 ports 1111 2222 10.0.0.0/8 ports 0 0  
and are instead creating entry with network: 192.168.0.0 and mask: 31  
..We also delete this line:  
        permit udp 192.168.0.1/32 ports 1111 2222 10.0.0.0/8 ports 0 0  
  
...  
Heres our ACL after deleting overlapping net entries  
        permit tcp 192.168.1.4/30 ports 1 4 0.0.0.0/0 ports 1 4  
        permit tcp 192.168.1.16/28 ports 1 4 0.0.0.0/0 ports 1 4  
        permit tcp 0.0.0.0/0 ports 1 4 192.168.1.4/30 ports 1 4  
        permit tcp 0.0.0.0/0 ports 1 4 192.168.1.16/28 ports 1 4  
        permit tcp 0.0.0.0/0 ports 0 0 192.168.1.42/32 ports 0 0  
        permit udp 192.168.0.0/31 ports 1111 2222 10.0.0.0/8 ports 0 0  
        permit udp 192.168.0.1/32 ports 3333 4444 10.0.0.0/8 ports 0 0  
  
...  
This line is fragmented and will consume an additional TCAM entry  
After adding this line  
        permit tcp 192.168.1.4/30 ports 1 4 0.0.0.0/0 ports 1 4  
we are now having total TCAM consumption of 10  
  
...  
This line is fragmented and will consume an additional TCAM entry  
After adding this line  
        permit tcp 192.168.1.16/28 ports 1 4 0.0.0.0/0 ports 1 4  
we are now having total TCAM consumption of 20  
  
...  
This line is fragmented and will consume an additional TCAM entry  
After adding this line  
        permit tcp 0.0.0.0/0 ports 1 4 192.168.1.4/30 ports 1 4  
we are now having total TCAM consumption of 30  
  
...  
This line is fragmented and will consume an additional TCAM entry  
After adding this line  
        permit tcp 0.0.0.0/0 ports 1 4 192.168.1.16/28 ports 1 4  
we are now having total TCAM consumption of 40  
  
...  
After adding this line  
        permit tcp 0.0.0.0/0 ports 0 0 192.168.1.42/32 ports 0 0  
we are now having total TCAM consumption of 41  
  
...  
This line is fragmented and will consume an additional TCAM entry  
After adding this line  
        permit udp 192.168.0.0/31 ports 1111 2222 10.0.0.0/8 ports 0 0  
we are now having total TCAM consumption of 43  
  
...  
This line is fragmented and will consume an additional TCAM entry  
After adding this line  
        permit udp 192.168.0.1/32 ports 3333 4444 10.0.0.0/8 ports 0 0  
we are now having total TCAM consumption of 45  
  
...  
Total TCAM usage = 46  
Including fragmented entries = 6  
LOU usage = 2

## Usage

Put your ACL contents in file named x.txt residing in the same directory with the script (just contents without the ACL name). Run the script.
