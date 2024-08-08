# Kernel Level Reference Monitor for File Protection  
This specification is related to a Linux Kernel Module (LKM) implementing a reference monitor for file protection. 

The reference monitor can be in one of the following four states:

<ul>
<li> OFF, meaning that its operations are currently disabled;
<li> ON, meaning that its operations are currently enabled; 
<li> REC-ON/REC-OFF, meaning that it can be currently reconfigured (in either ON or OFF mode). 
</ul>

The configuration of the reference monitor is based on a set of file system paths. Each path corresponds to a file/dir that cannot be currently opened in write mode. Hence, any attempt to write-open the path needs to return an error, independently of the user-id that attempts the open operation.
Reconfiguring the reference monitor means that some path to be protected can be added/removed. In any case, changing the current state of the reference monitor requires that the thread that is running this operation needs to be marked with effective-user-id set to root, and additionally the reconfiguration requires in input a password that is reference-monitor specific. This means that the encrypted version of the password is maintained at the level of the reference monitor architecture for performing the required checks.

It is up to the software designer to determine if the above states ON/OFF/REC-ON/REC-OFF can be changed via VFS API or via specific system-calls. The same is true for the services that implement each reconfiguration step (addition/deletion of paths to be checked). Together with kernel level stuff, the project should also deliver user space code/commands for invoking the system level API with correct parameters.

In addition to the above specifics, the project should also include the realization of a file system where a single append-only file should record the following tuple of data (per line of the file) each time an attempt to write-open a protected file system path is attempted:

<ul>
	<li>the process TGID
	<li>the thread ID
	<li>the user-id
	<li>the effective user-id
	<li>the program path-name that is currently attempting the open
	<li> a cryptographic hash of the program file content
		
</ul>
		
The the computation of the cryptographic hash and the writing of the above tuple should be carried in deferred work.



> REFS:
[Linux Kernel Doc](https://www.kernel.org/doc/html/latest/index.html)


# Project ideas
L'idea fondamentale e' quella di usare i kernel object per gestire in modo uniforme tutte le directory e/o i file da proteggere. Si parte dal creare un kobject sotto `/sys`, tipo `/sys/rmfs` (*reference monitor file system*) che contiene un file di stato `state`. Tramite `show/store_state()` gestisco lo stato del reference monitor.

Sono indeciso su come gestire le operazioni su file e directory. 
- Un opzione potrebbe essere quella di mantenere un secondo file sotto `/sys/rmfs/` file dove in ogni riga mantengo i full-path da proteggere. Leggendo il file posso capire se un path e' protetto o meno.
- Un'altra opzione e' quella di separare in una struttura ad albero i vari percorsi. Quindi mantenere una directory sotto `/sys/rmfs`, tipo `/sys/rmfs/paths` e creare a catena directory e/o file per mimare la struttura del file system reale. In questo modo, posso controllare se un path e' protetto o meno semplicemente controllando se esiste o meno il path sotto `/sys/rmfs/paths/`.

In entrambi i casi pensavo di implementare delle kprobe per intercettare le operazioni di open (in particolare `vfs_open()` visto che e' l'ultima chiamata fatta dal kernel prima di invocare le effettive driver-specific operations) per controllare se il path e' protetto prima dell'apertura effettiva e in caso bloccare l'operazione. Questo perche' le operazioni di show e store dei singoli kobject non penso che si riflettano in modo diretto sulle operazioni di open degli oggetti da proteggere. 

> Non so se mi sono spiegato. Quello che intendo e' che se faccio una `open()` su un file (es. `/home/user/file.txt`) il kernel non invoca operazioni di show/store sui kobject relativi a `/sys/rmfs/paths/home/user/file.txt`. Quindi devo intercettare l'operazione di open per controllare se il path e' protetto o meno: sostanzialmente forzo il kernel a invocare le show prima di fare effettivamente l'open.

Per la parte di logging in deferred work non ci ho ancora pensato ma non credo che sia niente di difficile e penso che sia sufficiente usare una `workqueue` per fare il logging, magari gestendo il file tramite RCU per evitare di overlappare le operazioni di scrittura.