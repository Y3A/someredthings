#include <Windows.h>
#include <stdio.h>
#include <initguid.h>
#include <MSTask.h>

#pragma comment(lib, "ole32")

// https://learn.microsoft.com/en-us/windows/win32/taskschd/c-c-code-example-creating-a-task-using-newworkitem

#define warn(x, y) printf("%s : 0x%08X\n", x, y);

int main(void)
{
    HRESULT         hr = S_OK;
    ITaskScheduler  *pITS = NULL;
    LPCWSTR         pwszTaskName;
    LPWSTR          lpwUserName = NULL;
    DWORD           cbUserName = 128 * sizeof(wchar_t);
    ITask           *pITask = NULL;
    IPersistFile    *pIPersistFile = NULL;

    // Call CoInitialize to initialize the COM library and then 
    // call CoCreateInstance to get the Task Scheduler object. 
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (!SUCCEEDED(hr)) {
        warn("CoInitializeEx fail", hr);
        return 0;
    }

    hr = CoCreateInstance(
        CLSID_CTaskScheduler,
        NULL,
        CLSCTX_INPROC_SERVER,
        IID_PPV_ARGS(&pITS)
    );
    if (!SUCCEEDED(hr)) {
        warn("CoCreateInstance fail", hr);
        goto out;
    }

    puts("Task Scheduler Interface instantiated");

    // Call ITaskScheduler::NewWorkItem to create new task.
    pwszTaskName = L"CommandTask";

    hr = pITS->NewWorkItem(pwszTaskName, // Name of task
        CLSID_CTask,          // Class identifier 
        IID_ITask,            // Interface identifier
        (IUnknown **)&pITask // Pointer to task 
    );
    if (!SUCCEEDED(hr) && hr == 0x80070050) {
        warn("ITaskScheduler::NewWorkItem fail", hr);
        puts("Trying to delete task and try again");
        hr = pITS->Delete(pwszTaskName);
        if (!SUCCEEDED(hr)) {
            warn("ITaskScheduler::Delete fail", hr);
            puts("exiting");
            goto out;
        }
        puts("Task removed");
        hr = pITS->NewWorkItem(pwszTaskName, // Name of task
            CLSID_CTask,          // Class identifier 
            IID_ITask,            // Interface identifier
            (IUnknown **)&pITask // Pointer to task 
        );
        if (!SUCCEEDED(hr)) {
            warn("ITaskScheduler::NewWorkItem fail", hr);
            goto out;
        }
    }

    // set task parameters: comment, name, working directory, params if you wish
    pITask->SetApplicationName(L"C:\\Windows\\System32\\cmd.exe");
    if (!SUCCEEDED(hr)) {
        warn("ITask::SetApplicationName fail", hr);
        goto out;
    }

    pITask->SetWorkingDirectory(L"C:\\Windows\\System32");
    if (!SUCCEEDED(hr)) {
        warn("ITask::SetWorkingDirectory fail", hr);
        goto out;
    }

    pITask->SetParameters(L"/k whoami /all");
    if (!SUCCEEDED(hr)) {
        warn("ITask::SetParameters fail", hr);
        goto out;
    }

    lpwUserName = (LPWSTR)HeapAlloc(GetProcessHeap(), 0, cbUserName);
    if (!lpwUserName) {
        warn("HeapAlloc fail", GetLastError());
        goto out;
    }

    if (!GetUserNameW(lpwUserName, &cbUserName)) {
        warn("GetUserNameW fail", GetLastError());
        goto out;
    }

    wprintf(L"Username: %s\n", lpwUserName);

    pITask->SetAccountInformation(lpwUserName, NULL); // required
    if (!SUCCEEDED(hr)) {
        warn("ITask::SetAccountInformation fail", hr);
        goto out;
    }

    // set flags
   hr = pITask->SetFlags(TASK_FLAG_RUN_ONLY_IF_LOGGED_ON | TASK_FLAG_HIDDEN);
   if (!SUCCEEDED(hr)) {
       warn("ITask::SetFlags fail", hr);
       goto out;
   }

   // get a pointer to IPersistFile
   hr = pITask->QueryInterface(
       IID_PPV_ARGS(&pIPersistFile)
   );
   if (!SUCCEEDED(hr)) {
       warn("ITask::QueryInterface fail", hr);
       goto out;
   }

   // save the new task to disk
   hr = pIPersistFile->Save(NULL, TRUE);
   pIPersistFile->Release();
   if (!SUCCEEDED(hr)) {
       warn("IPersistFile::Save fail", hr);
       goto out;
   }

   puts("Created task.");

   // run the task
   hr = pITask->Run();
   if (!SUCCEEDED(hr)) {
       warn("ITask::Run fail", hr);
       goto out;
   }

   Sleep(2000);
   puts("Task ran.");
   puts("Check C:\\Windows\\Tasks folder");

   // and remove the task
   pITS->Delete(pwszTaskName);
   puts("Task removed");

out:
   if (pITS)
       pITS->Release();
   if (pITask)
       pITask->Release();
   if (lpwUserName)
       HeapFree(GetProcessHeap(), 0, lpwUserName);

   CoUninitialize();
   return 0;
}
