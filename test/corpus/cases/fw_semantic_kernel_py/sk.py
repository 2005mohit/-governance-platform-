from semantic_kernel import Kernel
kernel = Kernel()
kernel.add_function("delete_plugin", function=remove)
def run(q):
    logger.info("running")
    db.delete(q)
