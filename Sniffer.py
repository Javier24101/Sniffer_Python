import socket
import struct
def BytesAWords(L8):
    L16 = []
    if len(L8)%2 != 0:
        L8.append(0)
    for i in range(0, len(L8), 2):
        L16.append(L8[i]*256 + L8[i+1])
    return L16


def calcular_checksum(palabras):
    suma = sum(palabras)
    while suma >> 16:
        suma = (suma & 0xFFFF) + (suma >> 16)
    return ~suma & 0xFFFF


def obtener_cabecera_ip(datos_recibidos):
    print("**********INTERNET PROTOCOL**********")

    if len(datos_recibidos) < 20:
        print("Paquete demasiado corto para ser IPv4, descartado")
        return
 
    version_check = datos_recibidos[0] >> 4
    if version_check != 4:
        print(f"Paquete no IPv4 (version = {version_check}), descartado")
        return
    valores_desempaquetados = struct.unpack('!BBHHHBBH4s4s', datos_recibidos[:20])

    version_ihl = valores_desempaquetados[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0x0F
    tamano_cabecera = ihl * 4

    tipo_servicio, longitud_total, id_paquete, flags_offset, ttl, protocolo, checksum = valores_desempaquetados[1:8]
    
    ip_origen_bytes = valores_desempaquetados[8]
    ip_destino_bytes = valores_desempaquetados[9]
    ip_origen = socket.inet_ntoa(ip_origen_bytes)
    ip_destino = socket.inet_ntoa(ip_destino_bytes)

    flags = flags_offset >> 13
    desplazamiento = flags_offset & 0x1FFF

    ip_header_full = list(datos_recibidos[:ihl * 4])
    ip_header_full[10] = 0
    ip_header_full[11] = 0
    words = BytesAWords(ip_header_full)
    calculated_checksum = calcular_checksum(words)

    print(f"Version IP = {version}")
    print(f"IHL = {ihl * 4} bytes")
    print(f"TOS = {tipo_servicio}")
    print(f"Longitud Total = {longitud_total} bytes")
    print(f"Identificacion = {id_paquete}")
    print(f"Flags = {bin(flags)}")
    if (flags & 0b010):
        print(" Don't Fragment")
    if (flags & 0b001):
        print(" More Fragments")
    print(f"Desplazamiento Fragmento = {desplazamiento}")
    print(f"TTL = {ttl}")
    print(f"Protocolo = {protocolo}")
    print(f"Checksum = {checksum} ({'valido' if checksum == calculated_checksum else 'erroneo'})")
    print(f"IP origen = {ip_origen}")
    print(f"IP destino = {ip_destino}")

    if ihl > 5:
        print(f"Opciones IP = {datos_recibidos[20:tamano_cabecera]}")

    payload = datos_recibidos[tamano_cabecera:]
    
    match protocolo:
        case 1 | 6 | 17:
            decodificar_protocolo(protocolo, ip_origen_bytes, ip_destino_bytes, payload)
        case _:
            print(f"Datos IP = {payload}")


def obtener_cabecera_udp(bytes_ip_origen, bytes_ip_destino, payload):
    print("**********USER DATAGRAM PROTOCOL**********")
    cabecera_udp = payload[:8]
    puerto_origen, puerto_destino, longitud, checksum = struct.unpack('!HHHH', cabecera_udp)

    pseudo_cabecera = struct.pack('!4s4sBBH', bytes_ip_origen, bytes_ip_destino, 0, 17, len(payload))
    datos_checksum = list(pseudo_cabecera + payload)
    palabras = BytesAWords(datos_checksum)
    checksum_calculado = calcular_checksum(palabras)

    print(f"Puerto origen = {puerto_origen}")
    print(f"Puerto destino = {puerto_destino}")
    print(f"Longitud = {longitud} bytes")
    if checksum == 0:
        print(f"Checksum = {checksum} (no calculado)")
    else:
        estado_checksum = 'valido' if checksum_calculado == 0 else 'erroneo'
        print(f"Checksum = {checksum} ({estado_checksum})")

    if puerto_origen == 53 or puerto_destino == 53:
        procesar_mensaje_dns(payload[8:])
    else:
        print(f"Datos UDP = {payload[8:]}")


def obtener_cabecera_tcp(bytes_ip_origen, bytes_ip_destino, payload):
    print("**********TRANSMISSION CONTROL PROTOCOL**********")
    
    src_port, dst_port, seq, ack, offset_reserved_flags, window, checksum, urg_ptr = struct.unpack('!HHLLHHHH', payload[:20])

    offset = (offset_reserved_flags >> 12) * 4
    flags = offset_reserved_flags & 0x3F

    URG = (flags >> 5) & 1
    ACK = (flags >> 4) & 1
    PSH = (flags >> 3) & 1
    RST = (flags >> 2) & 1
    SYN = (flags >> 1) & 1
    FIN = flags & 1

    pseudo_cabecera = struct.pack('!4s4sBBH', bytes_ip_origen, bytes_ip_destino, 0, 6, len(payload))
    checksum_calculado = calcular_checksum(BytesAWords(list(pseudo_cabecera + payload)))

    opciones = payload[20:offset] if offset > 20 else b''
    datos_tcp = payload[offset:]

    print(f"Puerto origen = {src_port}")
    print(f"Puerto destino = {dst_port}")
    print(f"Numero secuencia = {seq}")
    print(f"Numero asentimiento = {ack}")
    print(f"Longitud cabecera = {offset} bytes")
    print("Flags:")
    print(f"  URG: {URG}, ACK: {ACK}, PSH: {PSH}, RST: {RST}, SYN: {SYN}, FIN: {FIN}")

    print(f"Ventana = {window}")
    estado_checksum = 'valido' if checksum_calculado == 0 else 'erroneo'
    print(f"Checksum = {hex(checksum)} ({estado_checksum})")
    print(f"Puntero urgente = {urg_ptr}")
    
    if opciones:
        print(f"Opciones = {opciones}")
    print(f"Datos TCP = {datos_tcp}")

    if src_port == 80 or dst_port == 80:
        print("--- HTTP ---")
        print(datos_tcp.decode('utf-8', errors='ignore'))
    elif src_port == 25 or dst_port == 25:
        print("--- SMTP ---")
        print(datos_tcp.decode('utf-8', errors='ignore'))
    elif src_port == 21 or dst_port == 21:
        print("--- FTP ---")
        print(datos_tcp.decode('utf-8', errors='ignore'))


def interpretar_tipo_codigo_icmp(tipo_icmp, codigo):
    match tipo_icmp:
        case 0:
            print("Mensaje: Respuesta de eco")
        case 8:
            print("Mensaje: Peticion de eco")
        case 11:
            print("Mensaje: Tiempo excedido")
            match codigo:
                case 0: print("Mensaje: TTL excedido")
                case 1: print("Mensaje: Tiempo de reensamblaje de fragmento excedido")
        case 3:
            print("Mensaje: Destino inalcanzable")
            match codigo:
                case 0: print("Mensaje: Red inalcanzable")
                case 1: print("Mensaje: Host inalcanzable")
                case 2: print("Mensaje: Protocolo inalcanzable")
                case 3: print("Mensaje: Puerto inalcanzable")
                case 4: print("Mensaje: Se requiere fragmentación, pero DF=1")
                case 5: print("Mensaje: Error en la ruta de origen")
                case 6: print("Mensaje: Red de destino desconocida")
                case 7: print("Mensaje: Host de destino desconocido")
                case 8: print("Mensaje: Error de aislamiento del host de origen")
                case 9: print("Mensaje: Acceso a la red prohibida")
                case 10: print("Mensaje: Acceso al host prohibido")
                case 11: print("Mensaje: Red inalcanzable para el TOS")
                case 12: print("Mensaje: Host inalcanzable para el TOS")
        case 4:
            print("Mensaje: Disminucion del origen")
        case 5:
            print("Mensaje: Redireccion")
            match codigo:
                case 0: print("Mensaje: Redireccion para la red")
                case 1: print("Mensaje: Redireccion para el host")
                case 2: print("Mensaje: Redireccion para TOS y red")
                case 3: print("Mensaje: Redireccion para TOS y host")
        case 12:
            print("Mensaje: Problema de parametros")
        case 13:
            print("Mensaje: Solicitud de marca de tiempo")
        case 14:
            print("Mensaje: Respuesta de marca de tiempo")
        case _:
            print(f"Tipo ICMP {tipo_icmp} desconocido")


def obtener_cabecera_icmp(payload):
    print("**********INTERNET CONTROL MESSAGE PROTOCOL**********")
    icmp_header = payload[:8]
    icmp_type, code, checksum, rest = struct.unpack('!BBHI', icmp_header)

    icmp_bytes = list(payload)
    words = BytesAWords(icmp_bytes)
    calculated_checksum = calcular_checksum(words)

    print(f"Tipo = {icmp_type}")
    print(f"Codigo = {code}")
    print(f"Checksum = {hex(checksum)} ({'valido' if calculated_checksum == 0 else 'erroneo'})")
    print(f"Resto cabecera = {hex(rest)}")
    interpretar_tipo_codigo_icmp(icmp_type, code)
    print(f"Datos = {payload[8:]}")


def leerNombreDNS(mensaje, posicion):
    nombre = ''
    saltoRealizado = False
    posicionFinal = posicion
    iteraciones = 0
    while iteraciones < 128:
        if posicion >= len(mensaje):
            break
        longitud = mensaje[posicion]
        if longitud == 0:
            if not saltoRealizado:
                posicionFinal = posicion + 1
            break
        if (longitud & 0xC0) == 0xC0:
            if posicion + 1 >= len(mensaje):
                break
            puntero = ((longitud & 0x3F) << 8) | mensaje[posicion + 1]
            if not saltoRealizado:
                posicionFinal = posicion + 2
                saltoRealizado = True
            posicion = puntero
        else:
            posicion += 1
            if posicion + longitud > len(mensaje):
                break
            etiqueta = mensaje[posicion:posicion + longitud].decode('utf-8', errors='ignore')
            if nombre == '':
                nombre = etiqueta
            else:
                nombre = nombre + '.' + etiqueta
            posicion += longitud
        iteraciones += 1
    return nombre, posicionFinal


def procesar_mensaje_dns(payload):
    print("**********DOMAIN NAME SYSTEM**********")
    if len(payload) < 12:
        print("Error: El mensaje DNS es demasiado corto")
        return

    transaction_id, flags, qdcount, ancount, nscount, arcount = struct.unpack('!HHHHHH', payload[:12])

    QR = flags >> 15
    OpCode = (flags >> 11) & 0x0F
    AA = (flags >> 10) & 0x01
    TC = (flags >> 9) & 0x01
    RD = (flags >> 8) & 0x01
    RA = (flags >> 7) & 0x01
    RCode = flags & 0x0F

    print(f"Transaction ID = {hex(transaction_id)}")
    if QR == 0:
        print(f"QR = {QR}, mensaje de consulta")
    else:
        print(f"QR = {QR}, mensaje de respuesta")
    print(f"  OpCode: {OpCode}, AA: {AA}, TC: {TC}, RD: {RD}, RA: {RA}, RCode: {RCode}")
    print(f"N consultas = {qdcount}")
    print(f"N respuestas = {ancount}")
    print(f"N autoridad = {nscount}")
    print(f"N adicionales = {arcount}")

    tiposDNS = {1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA'}
    posicion = 12

    for i in range(qdcount):
        nombre, posicion = leerNombreDNS(payload, posicion)
        if posicion + 4 > len(payload):
            break
        tipo = (payload[posicion] << 8) + payload[posicion + 1]
        clase = (payload[posicion + 2] << 8) + payload[posicion + 3]
        posicion += 4
        print(f"Consulta {i + 1}: {nombre}  Tipo = {tiposDNS.get(tipo, tipo)}  Clase = {clase}")

    for i in range(ancount):
        nombre, posicion = leerNombreDNS(payload, posicion)
        if posicion + 10 > len(payload):
            break
        tipo = (payload[posicion] << 8) + payload[posicion + 1]
        clase = (payload[posicion + 2] << 8) + payload[posicion + 3]
        ttl = struct.unpack('!L', payload[posicion + 4:posicion + 8])[0]
        rdlength = (payload[posicion + 8] << 8) + payload[posicion + 9]
        posicion += 10
        if posicion + rdlength > len(payload):
            break
        rdata = payload[posicion:posicion + rdlength]
        valor = ''
        if tipo == 1 and rdlength == 4:
            valor = socket.inet_ntoa(rdata)
        elif tipo == 28 and rdlength == 16:
            partes = []
            for j in range(0, 16, 2):
                partes.append(format((rdata[j] << 8) + rdata[j + 1], 'x'))
            valor = ':'.join(partes)
        elif tipo in (2, 5, 12):
            valor, _ = leerNombreDNS(payload, posicion)
        else:
            valor = str(rdata)
        posicion += rdlength
        print(f"Respuesta {i + 1}: {nombre}  Tipo = {tiposDNS.get(tipo, tipo)}  TTL = {ttl}  Valor = {valor}")


def decodificar_protocolo(id_protocolo, bytes_ip_origen, bytes_ip_destino, payload):
    match id_protocolo:
        case 17:
            obtener_cabecera_udp(bytes_ip_origen, bytes_ip_destino, payload)
        case 6:
            obtener_cabecera_tcp(bytes_ip_origen, bytes_ip_destino, payload)
        case 1:
            obtener_cabecera_icmp(payload)
        case _:
            print("No se ha reconocido el protocolo")


def main():
    print("===========================================")
    print("SNIFFER JAVIER RINCON VIVERO")
    print("REDES DE COMPUTADORES")
    print("===========================================")

    HOST = '192.168.1.20'

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    s.bind((HOST, 0))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    for i in range(100):
        print("================================")
        print(f"======= Paquete {i + 1} =======")
        print("================================")
        p = s.recvfrom(65565)
        datos = p[0]
        obtener_cabecera_ip(datos)

    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)


if __name__ == "__main__":
    main()
