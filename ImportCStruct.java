//
//@author Jan Mothes
//@category Data Types
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import structimporter.ParseStructDialog;

public class ImportCStruct extends GhidraScript {
	@Override
	protected void run() throws Exception {
		var dialog = new ParseStructDialog(this);
        state.getTool().showDialog(dialog);
	}
}
