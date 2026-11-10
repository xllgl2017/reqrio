
// #[test]
// fn net_websocket_echo() {
//     use std::sync::mpsc;
//     use std::time::Duration;
//
//     let (tx, rx) = mpsc::channel();
//     std::thread::spawn(move || {
//         let result = (|| -> Result<String, String> {
//             let mut ws = WebSocket::open_sync("wss://echo.websocket.org").map_err(|e| e.to_string())?;
//             ws.send_text("hello").wait().map_err(|e| e.to_string())?;
//             let frame = ws.read_frame().wait().map_err(|e| e.to_string())?;
//             let _ = ws.shutdown().wait();
//             Ok(String::from_utf8_lossy(frame.payload().as_bytes()).to_string())
//         })();
//         let _ = tx.send(result);
//     });
//
//     match rx.recv_timeout(Duration::from_secs(20)) {
//         Ok(Ok(payload)) => assert!(payload.contains("hello"), "payload = {}", payload),
//         Ok(Err(e)) => panic!("WebSocket failed: {}", e),
//         Err(_) => panic!("WebSocket timed out after 20s (wss://echo.websocket.org)"),
//     }
// }
