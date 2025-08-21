from blocks import Block


def list_blocks_to_bytes(blocks: list[Block]) -> bytes:
    """Convert a list of DataBlock objects to bytes."""
    for block in blocks:
        if not isinstance(block, Block):
            raise TypeError(f"Expected DataBlock, got {type(block).__name__}")
    return b"".join(block.to_bytes() for block in blocks)
