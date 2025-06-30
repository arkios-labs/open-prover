import ray
import uuid
import time

@ray.remote
class RegistryActor:
    def __init__(self):
        self.tasks = {}

    def register_task(self, task_id: str, metadata: dict = None):
        self.tasks[task_id] = {"metadata": metadata or {}, "status": "registered"}
        print(f"Registered: {task_id}")

    def update_status(self, task_id: str, status: str):
        if task_id in self.tasks:
            self.tasks[task_id]["status"] = status

    def get_task_info(self, task_id: str):
        return self.tasks.get(task_id, None)

@ray.remote
def process_task(task_id: str, registry_handle):
    print(f"Running task {task_id}")
    ray.get(registry_handle.update_status.remote(task_id, "running"))
    time.sleep(1)
    ray.get(registry_handle.update_status.remote(task_id, "completed"))
    return f"{task_id} done"

if __name__ == "__main__":
    ray.init()

    registry = RegistryActor.options(name="registry", lifetime="detached").remote()

    task_ids = [str(uuid.uuid4()) for _ in range(3)]
    for tid in task_ids:
        ray.get(registry.register_task.remote(tid))

    print("Initial Task Statuses:")
    for tid in task_ids:
        info = ray.get(registry.get_task_info.remote(tid))
        print(f"[{tid}] -> {info}")

    result1 = process_task.remote(task_ids[0], registry)
    result2 = process_task.remote(task_ids[1], registry)
    result3 = process_task.remote(task_ids[2], registry)

    final = ray.get([result1, result2, result3])

    print("Results:")
    for tid in task_ids:
        info = ray.get(registry.get_task_info.remote(tid))
        print(f"[{tid}] -> {info}")

    ray.shutdown()
