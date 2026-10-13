//! Fetch a market estimate inside the board process before preparing its PSBT.
use anyhow::{Context,Result};
use bark::chain::ChainSource;
use bitcoin::FeeRate;

pub async fn regular(chain: &ChainSource) -> Result<FeeRate> {
    // A new adapter process has only the configured fallback in memory.
    // No fallback is permitted when preparing a new financial commitment.
    chain.update_fee_rates(None).await.context("board market fee estimate unavailable")?;
    Ok(chain.fee_rates().await.regular)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bark::chain::ChainSourceSpec;
    use bitcoin::Network;
    use std::{io::{Read,Write},net::TcpListener,sync::{Arc,Mutex,atomic::{AtomicBool,Ordering}},thread,time::Duration};

    struct Backend {
        url: String,
        calls: Arc<Mutex<Vec<String>>>,
        stop: Arc<AtomicBool>,
        thread: Option<thread::JoinHandle<()>>,
    }
    impl Backend {
        fn new(fees: &'static str) -> Self {
            let listener=TcpListener::bind("127.0.0.1:0").unwrap();
            let url=format!("http://{}",listener.local_addr().unwrap());
            listener.set_nonblocking(true).unwrap();
            let calls=Arc::new(Mutex::new(Vec::new()));let observed=calls.clone();
            let stop=Arc::new(AtomicBool::new(false));let done=stop.clone();
            let thread=thread::spawn(move || {
                while !done.load(Ordering::SeqCst) {
                    let (mut stream,_)=match listener.accept() {
                        Ok(value)=>value,
                        Err(e) if e.kind()==std::io::ErrorKind::WouldBlock=>{thread::sleep(Duration::from_millis(5));continue;},
                        Err(e)=>panic!("{e}"),
                    };
                    stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                    let mut request=Vec::new();let mut bytes=[0;1024];
                    while !request.windows(4).any(|w|w==b"\r\n\r\n") {
                        let n=stream.read(&mut bytes).unwrap();assert!(n>0);
                        request.extend_from_slice(&bytes[..n]);assert!(request.len()<=8192);
                    }
                    let request=String::from_utf8(request).unwrap();
                    let path=request.lines().next().unwrap().split_whitespace().nth(1).unwrap().to_string();
                    observed.lock().unwrap().push(path.clone());
                    let body=match path.as_str() {
                        "/block-height/0"=>"00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6",
                        "/fee-estimates"=>fees,
                        _=>panic!("unexpected board quote request {path}"),
                    };
                    write!(stream,"HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).unwrap();
                }
            });
            Self{url,calls,stop,thread:Some(thread)}
        }
        async fn chain(&self) -> ChainSource {
            ChainSource::new(ChainSourceSpec::Esplora{url:self.url.clone()},Network::Signet,
                Some(FeeRate::BROADCAST_MIN)).await.unwrap()
        }
    }
    impl Drop for Backend {
        fn drop(&mut self) {self.stop.store(true,Ordering::SeqCst);self.thread.take().unwrap().join().unwrap();}
    }

    #[tokio::test]
    async fn fresh_board_process_uses_backend_rate_instead_of_its_initial_fallback() {
        let backend=Backend::new(r#"{"1":10.0,"3":2.5,"6":1.125}"#);
        let chain=backend.chain().await;
        assert_eq!(chain.fee_rates().await.regular,FeeRate::BROADCAST_MIN);
        assert_eq!(regular(&chain).await.unwrap().to_sat_per_kwu(),625);
        assert_eq!(*backend.calls.lock().unwrap(),vec!["/block-height/0","/fee-estimates"]);
    }

    #[tokio::test]
    async fn unavailable_regular_rate_is_a_gap_without_a_fallback_quote() {
        let backend=Backend::new(r#"{"1":10.0,"6":1.125}"#);
        let chain=backend.chain().await;
        assert!(regular(&chain).await.is_err());
        assert_eq!(*backend.calls.lock().unwrap(),vec!["/block-height/0","/fee-estimates"]);
    }
}
