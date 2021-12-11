loadLibrary = function(libFileName, search)
	paths = [""]
	if search then paths = [current_path, "/lib", "/bin", "/usr/bin", "/root", "/home/guest", "/"]
	for p in paths
		lib = include_lib(p+"/"+libFileName)
		if lib then return lib
	end for
	
	return false
end function

loadMetaXPloit = function()
	return loadLibrary("metaxploit.so", true)
end function

metaxploit = loadMetaXPloit

comp = get_shell.host_computer

if not metaxploit then exit("Error: metaxploit.so not found!")

if params.len < 1 then
    exit("Netcat (restricted edition) - By Nameless9000\n\nnc -nlvp PORT | nc -lvnp PORT -- Listen for connections\nnc -c bash IP PORT | nc -c bash IP PORT -- Start terminal")
end if

checkForRShell = function(ipAddr, checkPort)
    router = get_router(ipAddr)
    ports = router.used_ports
    
    if ports == null then return false
    if typeof(ports) == "string" then return false
    
    if(ports.len == 0) then return false

    for port in ports
        service_info = router.port_info(port)
        lan_ips = port.get_lan_ip

        if str(port.port_number) == checkPort then return true
    end for

    return false
end function

if params.len == 2 then
    opt = params[0]
    port = params[1]

    if opt == "-nlvp" or opt == "-lvnp" then
        ipAddr = comp.public_ip
        if checkForRShell(ipAddr, port) == false then exit("Error: port not found")

        fileName = comp.File(program_path).name

        print(fileName+": listening on "+ipAddr+" "+port+" ...")

        shells = []
        while shells.len == 0	
            shells = metaxploit.rshell_server
            if(typeof(shells) == "string") then exit(shells)	
            if(shells.len == 0) then wait(2)
        end while

        shell = shells[0]

        scomp = shell.host_computer

        print("Connected to "+scomp.public_ip+" : "+scomp.local_ip)

        output = scomp.show_procs
        lines = output.split("\n")
        for line in lines
            proc = line.split(" ")
            id = proc[1]
            pName = proc[4]

            if pName == "NetCat" then
                scomp.close_program(id.to_int)
            end if
        end for

        shell.start_terminal
    end if
end if

if params.len == 4 then
    opt = params[0]
    cmd = params[1]
    ip = params[2]
    port = params[3]

    if opt == "-c" and cmd == "bash" then
        if checkForRShell(ip, port) == false then exit("Error: ip/port not found")

        output = metaxploit.rshell_client(ip, port.to_int, "NetCat")
        if output != 1 then exit(output)

        exit("Success.")
    end if
end if

exit("Error: unknown command")
