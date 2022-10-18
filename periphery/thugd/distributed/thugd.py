import asyncio
import json
import logging
import signal

from aio_pika import connect_robust
from aio_pika.message import IncomingMessage, Message
from thug.ThugAPI import ThugAPI

logger = logging.getLogger(__name__)

THUG_SERVICE = "/home/thug/distributed/thug_service.py"
THUG_CONF = "/etc/thug"

def register_signals(loop):
    signals = (signal.SIGHUP, signal.SIGTERM, signal.SIGINT)
    for s in signals:
        loop.add_signal_handler(s, lambda s=s: asyncio.create_task(shutdown(s, loop)))

    logger.info("Registered signal handlers")
    

async def shutdown(recv_sig, loop):
    """
    Stops all tasks to enable controlled shutdown behaviour
    See Hattingh, Using AsyncIO in Python, p. 68 and
    https://gist.github.com/nvgoldin/30cea3c04ee0796ebd0489aa62bcf00a
    for code reference.

    """
    logger.info(f"Received exit signal {recv_sig.name}...")

    # To avoid multiple executions
    loop.remove_signal_handler(recv_sig.SIGTERM)
    loop.remove_signal_handler(recv_sig.SIGINT)
    loop.remove_signal_handler(recv_sig.SIGHUP)

    tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    try:
        [task.cancel() for task in tasks]
        logger.info(f"Cancelling {len(tasks)} tasks")

        await asyncio.gather(*tasks, return_exceptions=True)

    except Exception as e:
        logger.info(e)

    logger.info(f"Cancelled {len(tasks)} tasks")
    loop.stop()


async def initiate_thug_analysis(url, timeout, referrer):
   
    # try:
    # # Calls Python wrapped Thug
    result = await run_command(
        "python3",
        THUG_SERVICE,
        "-u",
        url,
        "-t",
        str(timeout),
        "-r",
        referrer,
        "-c",
        THUG_CONF
    )
    return result
    # except BaseException as e:
    #     logger.debug(e)
    #     logger.debug(f"Thug analysis of {url} failed")

    return None


async def run_command(*args):
    """
    See https://asyncio.readthedocs.io/en/latest/subprocess.html for background info
    :param args: varargs
    :return:
    """
    # Create subprocess, stdout must a pipe to be accessible as process.stdout
    process = await asyncio.create_subprocess_exec(
        *args, stdout=asyncio.subprocess.PIPE
    )

    # Await the subprocess to finish
    stdout, stderr = await process.communicate()

    # Return stdout
    return stdout


class Thugd():
    
    def __init__(self,):
        "docstring"
        self.channel = None
        
    async def on_message(self, message: IncomingMessage):        
        logger.debug(f"Server received: {str(message.body)} ==> {message}")

        if not self.channel:
            return

        loop = asyncio.get_running_loop()    
        job = json.loads(message.body.decode())
        print(job)
        async def run_in_background():
            json_bytes = await initiate_thug_analysis(**job)
            
            if not json_bytes:
                json_bytes = b""
                
            await self.channel.default_exchange.publish(
                Message(body=json_bytes),
                routing_key=message.reply_to,
            )
            
        loop.create_task(run_in_background()) 


    async def run(self):
        connection = await connect_robust("amqp://guest:guest@localhost")
        
        self.channel = await connection.channel()
        queue = await self.channel.declare_queue(
            "rpc.server.queue", exclusive=True, auto_delete=True
        )
        await queue.consume(self.on_message)
        
        return connection

    
if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    
    # Handles SIGINT, SIGTERM, SIGHUP
    register_signals(loop)
    
    t = Thugd()
    connection = loop.run_until_complete(t.run())

    # Runs the loop until shutdown is induced by signaling
    try:
        loop.run_forever()

    except asyncio.CancelledError as e:
        loop.run_until_complete(connection.close())
        loop.shutdown_asyncgens()
