//
//@author Jan Mothes
//@category Data Types
//@menupath
//@toolbar

import docking.DialogComponentProvider;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.cparser.C.CParser;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.util.exception.DuplicateNameException;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;

public class ImportCStruct extends GhidraScript {

    @Override
    protected void run() throws Exception {
        var dialog = new ParseStructDialog();
        state.getTool().showDialog(dialog);
    }
    
    static class CategoryTreeNode extends GTreeNode {
    	public final Category cat;
		public CategoryTreeNode(Category cat) {
			this.cat = cat;
		}
		@Override
		public String getName() {
			return cat.getName();
		}
		@Override
		public Icon getIcon(boolean expanded) {
			return null;
		}
		@Override
		public String getToolTip() {
			return cat.getCategoryPathName();
		}
		@Override
		public boolean isLeaf() {
			return cat.getCategories().length <= 0;
		}
    }


    class ParseStructDialog extends DialogComponentProvider {
        private final DataTypeManager dtm;
        private final List<DataType> parsedTypes;
        
        private GTree categoryTree;
        private JPanel parsedTypesPanel;
        
        private JTextArea textInput;
        private JTextArea typeOutput;

        private JButton parseButton;
        
        private List<Runnable> whenShown;
        

        private ParseStructDialog() {
            super("Parse Data Type", false, true, true, true);
            setPreferredSize(500, 400);

            parsedTypes = new ArrayList<>();
            whenShown = new ArrayList<>();
            
            // Parser Setup
            dtm = currentProgram.getDataTypeManager();
            
            // GUI SETUP
            this.addCancelButton();
            this.parseButton = new JButton("Parse");
            this.parseButton.addActionListener(event -> { this.parseType();});
            this.parseButton.setToolTipText("Parse the struct and preview the result");

            this.addButton(parseButton);

            this.addApplyButton();
            this.setApplyToolTip("Add list of parsed types");
            this.setApplyEnabled(false);

            var categorySelectorGui = buildCategorySelectorGui();
            var textInputGui = buildDataTypesGui();
            
            var splitter = new JSplitPane(JSplitPane.VERTICAL_SPLIT, categorySelectorGui, textInputGui);

            addWorkPanel(splitter);
            whenShown.add(() -> {
            	splitter.setDividerLocation(0.3);
            });
        }
        
        @Override
        protected void dialogShown() {
        	super.dialogShown();
        	for (var runnable : whenShown) {
        		runnable.run();
        	}
        }
        
        private GTreeNode buildCatTree(Category cat) {
        	var node = new CategoryTreeNode(cat);
        	for (var child : cat.getCategories()) {
            	var childNode = buildCatTree(child);
            	node.addNode(childNode);
            }
        	return node;
        }
        
        private JComponent buildCategorySelectorGui() {
        	// category tree
            var label = new JLabel("Select category for imported structs:");
            label.setAlignmentX(Component.LEFT_ALIGNMENT);
        	
            var rootCat = dtm.getRootCategory();
            var rootNode = buildCatTree(rootCat);
            var tree = new GTree(rootNode);
            tree.addSelectionPath(rootNode.getTreePath());
            
            this.categoryTree = tree;
            
            var container = new JPanel();
            container.setLayout(new BoxLayout(container, BoxLayout.Y_AXIS));
            container.add(label);
            container.add(tree);
            return container;
        }
        
        private JComponent buildDataTypeListGui() {
        	var container = new JPanel();
            container.setLayout(new BoxLayout(container, BoxLayout.Y_AXIS));
            
            this.parsedTypesPanel = container;
            
            return container;
        }
        
        private JComponent buildDataTypeInputGui() {
        	var selector = buildDataTypeListGui();
        	
        	textInput = new JTextArea(12, 50);
            textInput.setWrapStyleWord(true);
            textInput.setLineWrap(true);
        	
        	var container = new JPanel();
            container.setLayout(new BoxLayout(container, BoxLayout.Y_AXIS));
            container.add(selector);
            container.add(textInput);
            return container;
        }
        
        
        private JComponent buildDataTypesGui() {
        	var typeInput = buildDataTypeInputGui();
        	typeInput.setMinimumSize(new Dimension(0, 0));// for splitpane
        	
            typeOutput = new JTextArea(12, 50);
            typeOutput.setWrapStyleWord(true);
            typeOutput.setLineWrap(true);
            typeOutput.setEditable(false);
            typeOutput.setMinimumSize(new Dimension(0, 0));// for splitpane

            var splitter = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, typeInput, typeOutput);
            whenShown.add(() -> {
            	splitter.setDividerLocation(0.5);
            });
            return splitter;
        }

        private void parseType() {
            var text = this.textInput.getText();
            var parser = new CParser(dtm);
            DataType type;
            try {
                type = parser.parse(text);
            } catch (ParseException e) {
                typeOutput.setText(e.toString());
                this.setApplyEnabled(false);
                return;
            }
            
            var selectedNode = (CategoryTreeNode) categoryTree.getSelectionModel().getLeadSelectionPath().getLastPathComponent();
            var selectedCategory = selectedNode.cat;
            try {
				type.setCategoryPath(selectedCategory.getCategoryPath());
			} catch (DuplicateNameException e) {
				// TODO show error to user
				return;
			}
            
            parsedTypes.add(type);
            createDataTypeListEntry(type);
            typeOutput.setText(type.toString());
            this.setApplyEnabled(true);
        }
        
        private void createDataTypeListEntry(DataType type) {
        	var container = new JPanel();
            //container.setLayout(new BoxLayout(container, BoxLayout.X_AXIS));
        	
        	var label = new JLabel(type.getCategoryPath().getName() + " ->  " + type.getName());
//        	var showButton = new JButton("show");
//        	showButton.addActionListener(event -> {
//        		// ...
//        	});
        	var removeButton = new JButton("remove");
        	removeButton.addActionListener(event -> {
        		var index = parsedTypes.indexOf(type);
        		parsedTypes.remove(index);
        		if (parsedTypes.isEmpty()) {
        			this.setApplyEnabled(false);
        		}
        		parsedTypesPanel.remove(index);
        		parsedTypesPanel.revalidate();
        	});
        	
            container.add(label, BorderLayout.LINE_START);
//            container.add(showButton);
            container.add(removeButton, BorderLayout.LINE_END);
        	
        	parsedTypesPanel.add(container);
        }

        @Override
        protected void applyCallback() {
            int transaction_id = dtm.startTransaction("Parsed");
            for (var type : parsedTypes) {
            	dtm.addDataType(type, null);
            }
            dtm.endTransaction(transaction_id, true);
            this.close();
        }
    }
}
