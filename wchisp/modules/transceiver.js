import { Packet } from "./packet.js";

export class Transceiver {
	#port;
	
	async open() {
		if(!("serial" in navigator)) {
			throw new Error("Web Serial API is unsupported by this browser");
		}
		
		try {
			this.#port = await navigator.serial.requestPort();
		} catch(err) {
			throw new Error("Serial port selection cancelled or permission denied", { cause: err });
		}
		
		try {
			await this.#port.open({
				baudRate: 115200,
				dataBits: 8,
				stopBits: 1,
				parity: "none",
				flowControl: "none"
			});
		} catch(err) {
			throw new Error("Error occurred attempting to open serial port", { cause: err });
		}
	}
	
	async transmitPacket(packet) {
		const writer = this.#port.writable.getWriter();
		
		await writer.write(packet.toBytes());
		
		writer.releaseLock();
	}
	
	async receivePacket(length, timeout_ms = 3000) {
		const bytes = new Uint8Array(length);
		let offset = 0, stop = false, error;
		// let iterations = 0;
		
		const reader = this.#port.readable.getReader();
		
		const timer = setTimeout(() => {
			// Timeout expired, so stop reading by releasing the reader lock.
			// This will cause any waiting reader.read() to throw an error.
			stop = true;
			reader.releaseLock();
		}, timeout_ms);
		
		while(!stop && offset < bytes.length) {
			try {
				const { value, done } = await reader.read();
				if(done) break;
				if(offset + value.length <= bytes.length) {
					bytes.set(value, offset);
					offset += value.length;
				} else {
					error = new Error("Unexpected data; received more than " + bytes.length + " bytes");
					break;
				}
			} catch(e) {
				// Catch the error thrown by the reader on timeout (or other
				// error) and re-throw a more suitable error.
				error = new Error("Timed-out after " + timeout_ms + " ms waiting to receive, or read failure");
				break;
			}
			// iterations++;
		}
		
		// console.debug("receive loop iterations", iterations);
		
		clearTimeout(timer);
		reader.releaseLock();
		
		if(error) throw error;
		
		return Packet.fromBytes(bytes);
	}
	
	async close() {
		if(this.#port !== undefined) {
			await this.#port.close();
		}
	}
}
