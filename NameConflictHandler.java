import javax.swing.JButton;
import javax.swing.JTextArea;

import docking.DialogComponentProvider;
import ghidra.app.script.GhidraState;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;

class NameConflictHandler extends DataTypeConflictHandler {
	
	static class PoorMansMultilineLabel extends JTextArea {
		public PoorMansMultilineLabel(String text) {
			super(text);
			this.setWrapStyleWord(true);
			this.setLineWrap(true);
			this.setEditable(false);
		}
	}
	
    static class NameConflictDialog extends DialogComponentProvider {
    	public ConflictResult result = null;
		private NameConflictDialog(DataType addedDataType, DataType existingDataType) {
			super("Datatype Name Conflict", true, true, true, true);
			this.setPreferredSize(400, 150);
			this.addOKButton();
			addReplaceButton();
			var dataTypeName = existingDataType.getDisplayName();
			var categoryName = existingDataType.getCategoryPath().getPath();
			var hasCategory = !existingDataType.getCategoryPath().isRoot();
			var textArea = new PoorMansMultilineLabel(
					"Datatype '" + dataTypeName + (hasCategory ? ("' in '" +  categoryName) : "") + "' exists already! "
					+ "Press 'ok' to skip.");
			this.addWorkPanel(textArea);
		}
		private void addReplaceButton() {
			var replaceButton = new JButton("Replace existing");
			replaceButton.addActionListener(e -> {
				result = ConflictResult.REPLACE_EXISTING;
				this.close();
			});
			this.addButton(replaceButton);
		}
		@Override
		protected void okCallback() {
			result = ConflictResult.USE_EXISTING;
			this.close();
		}
    }
	
	// Ghidra's resolution code will call this conflictHandler twice, if it is not equivalent,
	// and we don't want want to show our user choice dialog twice. so we need to buffer the first result.
	private ConflictResult bufferedResult = null;
	
	private GhidraState state;
	
	public NameConflictHandler(GhidraState state) {
		this.state = state;
	}
	
	@Override
	public ConflictResult resolveConflict(DataType addedDataType, DataType existingDataType) {
		if (bufferedResult == null) {
			var dialog = new NameConflictDialog(addedDataType, existingDataType);
	        state.getTool().showDialog(dialog);
	        bufferedResult = dialog.result;
		}
        return bufferedResult;
	}
	
	@Override
	public boolean shouldUpdate(DataType sourceDataType, DataType localDataType) {
		return false;
	}
	
	@Override
	public DataTypeConflictHandler getSubsequentHandler() {
		return this;
	}
}