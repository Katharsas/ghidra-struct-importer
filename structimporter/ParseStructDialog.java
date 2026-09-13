package structimporter;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;

import javax.swing.BoxLayout;
import javax.swing.Icon;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;
import javax.swing.SwingConstants;
import javax.swing.UIManager;

import org.apache.commons.lang3.exception.ExceptionUtils;

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

public class ParseStructDialog extends DialogComponentProvider {
    
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
    	
    private final DataTypeManager programDtm;
    private final List<DataType> parsedTypes;
    
    private GTree categoryTree;
    private JPanel parsedTypesPanel;
    
    private JTextArea textInput;
    private JTextArea typeOutput;

    private JButton parseButton;
    private JButton removeButton;
    
    private List<Runnable> whenShown;
    private NameConflictHandler conflictHandler;
    
    private JComponent selectedEntry;
    private DataType selectedType;
    

    public ParseStructDialog(GhidraScript scriptContext) {
        super("Parse Data Type", false, true, true, true);
        setPreferredSize(900, 500);

        parsedTypes = new ArrayList<>();
        whenShown = new ArrayList<>();
        
        // Parser Setup
        programDtm = scriptContext.getCurrentProgram().getDataTypeManager();
        conflictHandler = new NameConflictHandler(scriptContext.getState());
        
        // GUI SETUP
        this.addCancelButton();

        this.addApplyButton();
        this.setApplyToolTip("Add list of parsed types");
        this.setApplyEnabled(false);

        var categorySelectorGui = buildCategorySelectorGui();
        var textInputGui = buildDataTypesGui();
        
        var splitter = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, categorySelectorGui, textInputGui);

        addWorkPanel(splitter);
        whenShown.add(() -> {
        	splitter.setDividerLocation(0.23);
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
        var label = new JLabel(" Insert types into category:");
        label.setAlignmentX(Component.LEFT_ALIGNMENT);
    	
        var rootCat = programDtm.getRootCategory();
        var rootNode = buildCatTree(rootCat);
        var tree = new GTree(rootNode);
        tree.addSelectionPath(rootNode.getTreePath());
        tree.setAlignmentX(Component.LEFT_ALIGNMENT);
        
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
    	var container = new JPanel(new BorderLayout());
    	
    	textInput = new JTextArea(12, 50);
        textInput.setWrapStyleWord(true);
        textInput.setLineWrap(true);
        container.add(new JScrollPane(textInput), BorderLayout.CENTER);
        
        this.parseButton = new JButton("Parse");
        this.parseButton.addActionListener(event -> { this.parseType();});
        this.parseButton.setToolTipText("Parse the struct and preview the result");
    	
        container.add(this.parseButton, BorderLayout.SOUTH);
        
        return container;
    }
    
    private void onRemove(ActionEvent e) {
    	Objects.requireNonNull(selectedType);
    	Objects.requireNonNull(selectedEntry);

    	var index = parsedTypes.indexOf(selectedType);
    	
        parsedTypes.removeIf(t -> t == selectedType);
        if (parsedTypes.isEmpty()) {
            this.setApplyEnabled(false);
        }
        parsedTypesPanel.remove(selectedEntry);
        parsedTypesPanel.revalidate();

        selectedEntry = null;
        selectedType = null;
        
        this.removeButton.setVisible(false);
        typeOutput.setText("");
        
        // select item above
        if (index >= parsedTypes.size()) {
        	index = parsedTypes.size() - 1;
        }
        if (index >= 0 && index < parsedTypes.size()) {
            var nextEntry = (JButton) parsedTypesPanel.getComponent(index);
            var nextType = parsedTypes.get(index);
            selectEntry(nextEntry, nextType);
        }
    }
    
    private JComponent buildDataTypeInfoGui() {
    	typeOutput = new JTextArea(12, 50);
        typeOutput.setWrapStyleWord(true);
        typeOutput.setLineWrap(true);
        typeOutput.setEditable(false);
        typeOutput.setBackground(getBackground());
    	
    	var selector = buildDataTypeListGui();
    	var selectorContainer = new JPanel();
    	selectorContainer.setLayout(new BoxLayout(selectorContainer, BoxLayout.Y_AXIS));
    	selectorContainer.add(selector);
    	
    	var splitter = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
    			new JScrollPane(typeOutput), new JScrollPane(selectorContainer));
        whenShown.add(() -> {
        	splitter.setDividerLocation(0.5);
        });
        
        var container = new JPanel(new BorderLayout());
        container.add(splitter, BorderLayout.CENTER);
        
        this.removeButton = new JButton("Remove");
        this.removeButton.setVisible(false);
        this.removeButton.addActionListener(this::onRemove);
        container.add(this.removeButton, BorderLayout.SOUTH);
        
        return container;
    }
    
    private JComponent buildDataTypesGui() {
    	var typeInput = buildDataTypeInputGui();
    	typeInput.setMinimumSize(new Dimension(0, 0));// for splitpane
    	
    	var typeInfo = buildDataTypeInfoGui();
    	typeInfo.setMinimumSize(new Dimension(0, 0));// for splitpane

        var splitter = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, typeInput, typeInfo);
        whenShown.add(() -> {
        	splitter.setDividerLocation(0.45);
        });
        return splitter;
    }

    private void parseType() {
        var text = this.textInput.getText();
        var parser = new CParser(programDtm);
        
        try {
        	parser.parse(text);
        } catch (ParseException e) {
        	var stackTrace = ExceptionUtils.getStackTrace(e);
            typeOutput.setText(e.toString() + "\n\n" + stackTrace);
            return;
        }
        
        var parsed = new HashMap<String, DataType>();
        parsed.putAll(parser.getTypes());
        parsed.putAll(parser.getComposites());
        parsed.putAll(parser.getEnums());

        if (parsed.isEmpty()) {
        	typeOutput.setText("No type was found in the provided source!");
        	return;
        }
        
        var selectedNode = (CategoryTreeNode) categoryTree.getSelectionModel().getLeadSelectionPath().getLastPathComponent();
        var selectedCategoryPath = selectedNode.cat.getCategoryPath();
        
        for (var type : parsed.values()) {
        	try {
				type.setCategoryPath(selectedCategoryPath);
			} catch (DuplicateNameException e) {
				typeOutput.setText(e.toString());
				continue;
			}
        	createDataTypeListEntry(type);
        	typeOutput.setText(type.toString());
        	parsedTypes.add(type);
        	this.setApplyEnabled(true);
        }
    }
    
    private void selectEntry(JButton entryButton, DataType type) {
        if (selectedEntry != null) {
        	((JButton) selectedEntry).setBorderPainted(true);
            selectedEntry.setBackground(null);
        }

        entryButton.setBorderPainted(false);
        entryButton.setBackground(UIManager.getColor("Tree.selectionBackground"));
        
        selectedEntry = entryButton;
        selectedType = type;
        typeOutput.setText(type.toString());
        removeButton.setVisible(true);
    }
    
    private void createDataTypeListEntry(DataType type) {
    	var category = programDtm.getRootCategory().getName() + "/" + type.getCategoryPath().getName();
        var button = new JButton(type.getName() + " (" + category + ")");
        button.setHorizontalAlignment(SwingConstants.LEFT);
        button.setMargin(new Insets(2, 4, 2, 4));
        button.setMaximumSize(new Dimension(Integer.MAX_VALUE, button.getPreferredSize().height));// for splitpane

        button.addActionListener(event -> selectEntry(button, type));

        parsedTypesPanel.add(button);
        parsedTypesPanel.revalidate();
        
        selectEntry(button, type);
    }

    @Override
    protected void applyCallback() {
        int transaction_id = programDtm.startTransaction("Parsed");
        for (var type : parsedTypes) {
        	programDtm.addDataType(type, conflictHandler);
        }
        programDtm.endTransaction(transaction_id, true);
        this.close();
    }
}
