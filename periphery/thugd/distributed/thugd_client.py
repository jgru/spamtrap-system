import asyncio
import json

from aio_pika import connect_robust
from aio_pika.message import IncomingMessage, Message


async def on_message(message: IncomingMessage):
    #print(f"Client received: {str(message.body)}")
    if message.body != b"":
        print(f"Client received: {json.loads(message.body.decode())}")

async def main(url, timeout, referrer):
    connection = await connect_robust("amqp://guest:guest@localhost")

    async with connection:
        channel = await connection.channel()
        queue = await channel.declare_queue("amq.rabbitmq.reply-to")
        await queue.consume(
            on_message,
            no_ack=True,
        )
        job = {
            "url": url,
            "timeout": timeout,
            "referrer": referrer,
        }
        
        req = json.dumps(job).encode()
        
        await channel.default_exchange.publish(
            Message(body=req, reply_to="amq.rabbitmq.reply-to"),
            routing_key="rpc.server.queue",
        )
        await asyncio.sleep(25)


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    args = {"url": "https://gist.githubusercontent.com/jgru/eb686cffd278f9ffb10c4424958b3627/raw/134c8dfed78f225a6b8776e6ee3ffd75e4560a2c/publications-jgru.bib", "timeout": 8, "referrer": "http://bing.com"}
    loop.run_until_complete(main(**args))
