import java.util.Iterator;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.apache.commons.collections4.ListUtils;
import org.apache.commons.collections4.SetUtils;

import com.google.common.collect.Iterators;

import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataOrganization;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataTypePath;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.SourceArchive;
import ghidra.program.model.data.StandAloneDataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.util.UniversalID;
import ghidra.util.task.TaskMonitor;

@SuppressWarnings("hiding")
public class BufferedDataTypeManager extends StandAloneDataTypeManager {

	private final DataTypeManager targetDtm;
	
	public BufferedDataTypeManager(String rootName, DataTypeManager targetDtm) {
		super(rootName);
		
		this.targetDtm = targetDtm;
	}
	
	public Iterator<DataType> getAllDataTypesBuffered() {
		return super.getAllDataTypes();
	}
	
	public void getAllDataTypesBuffered(List<DataType> list) {
		super.getAllDataTypes(list);
	}
	
	@Override
	public boolean contains(DataType dataType) {
		return super.contains(dataType) || targetDtm.contains(dataType);
	}

	@Override
	public boolean containsCategory(CategoryPath path) {
		return super.containsCategory(path) || targetDtm.containsCategory(path);
	}
	
	@Deprecated
	@Override
	public DataType findDataType(String dataTypePath) {
		return Optional
				.ofNullable(super.findDataType(dataTypePath))
				.orElse(targetDtm.findDataType(dataTypePath));
	}
	
	@Override
	public DataType findDataTypeForID(UniversalID datatypeID) {
		return Optional
				.ofNullable(super.findDataTypeForID(datatypeID))
				.orElse(targetDtm.findDataTypeForID(datatypeID));
	}
	
	@Override
	public void findDataTypes(String name, List<DataType> list) {
		super.findDataTypes(name, list);
		targetDtm.findDataTypes(name, list);
	}
	
	@Override
	public void findDataTypes(String name, List<DataType> list, boolean caseSensitive, TaskMonitor monitor) {
		super.findDataTypes(name, list, caseSensitive, monitor);
		targetDtm.findDataTypes(name, list, caseSensitive, monitor);
	}
	
	@Override
	public void findEnumValueNames(long value, Set<String> enumValueNames) {
		super.findEnumValueNames(value, enumValueNames);
		targetDtm.findEnumValueNames(value, enumValueNames);
	}
	
	@Override
	public Iterator<Composite> getAllComposites() {
		return Iterators.concat(super.getAllComposites(), targetDtm.getAllComposites());
	}
	
	@Override
	public Iterator<DataType> getAllDataTypes() {
		return Iterators.concat(super.getAllDataTypes(), targetDtm.getAllDataTypes());
	}
	
	@Override
	public void getAllDataTypes(List<DataType> list) {
		super.getAllDataTypes(list);
		targetDtm.getAllDataTypes(list);
	}
	
	@Override
	public Iterator<Structure> getAllStructures() {
		return Iterators.concat(super.getAllStructures(), targetDtm.getAllStructures());
	}
	
	@Override
	public Category getCategory(CategoryPath path) {
		return Optional
				.ofNullable(super.getCategory(path))
				.orElse(targetDtm.getCategory(path));
	}
	
	@Override
	public Category getCategory(long id) {
		return Optional
				.ofNullable(super.getCategory(id))
				.orElse(targetDtm.getCategory(id));
	}
	
	@Override
	public int getCategoryCount() {
		return super.getCategoryCount() + targetDtm.getCategoryCount();
	}
	
	@Override
	public DataOrganization getDataOrganization() {
		return targetDtm.getDataOrganization();
	}
	
	@Override
	public DataType getDataType(CategoryPath path, String name) {
		return Optional
				.ofNullable(super.getDataType(path, name))
				.orElse(targetDtm.getDataType(path, name));
	}
	
	@Override
	public DataType getDataType(DataTypePath dataTypePath) {
		return Optional
				.ofNullable(super.getDataType(dataTypePath))
				.orElse(targetDtm.getDataType(dataTypePath));
	}
	
	@Override
	public DataType getDataType(long dataTypeID) {
		return Optional
				.ofNullable(super.getDataType(dataTypeID))
				.orElse(targetDtm.getDataType(dataTypeID));
	}
	
	@Override
	public DataType getDataType(SourceArchive sourceArchive, UniversalID datatypeID) {
		return Optional
				.ofNullable(super.getDataType(sourceArchive, datatypeID))
				.orElse(targetDtm.getDataType(sourceArchive, datatypeID));
	}
	
	@Override
	public DataType getDataType(String dataTypePath) {
		return Optional
				.ofNullable(super.getDataType(dataTypePath))
				.orElse(targetDtm.getDataType(dataTypePath));
	}
	
	@Override
	public int getDataTypeCount(boolean includePointersAndArrays) {
		return super.getDataTypeCount(includePointersAndArrays) + targetDtm.getDataTypeCount(includePointersAndArrays);
	}
	
	@Override
	public List<DataType> getDataTypes(SourceArchive sourceArchive) {
		return ListUtils.union(
				super.getDataTypes(sourceArchive),
				targetDtm.getDataTypes(sourceArchive));
	}
	
	@Override
	public Set<DataType> getDataTypesContaining(DataType dataType) {
		return SetUtils.union(
				super.getDataTypesContaining(dataType),
				targetDtm.getDataTypesContaining(dataType));
	}
	
	@Override
	public List<DataType> getFavorites() {
		return ListUtils.union(
				super.getFavorites(),
				targetDtm.getFavorites());
	}
	
	@Override
	public long getID(DataType dt) {
		long result = super.getID(dt);
		if (result == DataTypeManager.NULL_DATATYPE_ID) {
			result = targetDtm.getID(dt);
		}
		return result;
	}
	
	@Override
	public Pointer getPointer(DataType dt) {
		var dtm = dt.getDataTypeManager();
		if (dtm == null || dtm == this) {
			return super.getPointer(dt);
		} else {
			return targetDtm.getPointer(dt);
		}
	}
	
	@Override
	public Pointer getPointer(DataType dt, int size) {
		var dtm = dt.getDataTypeManager();
		if (dtm == null || dtm == this) {
			return super.getPointer(dt, size);
		} else {
			return targetDtm.getPointer(dt, size);
		}
	}
	
	@Override
	public SourceArchive getSourceArchive(UniversalID sourceID) {
		return Optional
				.ofNullable(super.getSourceArchive(sourceID))
				.orElse(targetDtm.getSourceArchive(sourceID));
	}
	
	@Override
	public List<SourceArchive> getSourceArchives() {
		return ListUtils.union(
				super.getSourceArchives(),
				targetDtm.getSourceArchives());
	}
	
	@Override
	public boolean isFavorite(DataType dataType) {
		return super.isFavorite(dataType) || targetDtm.isFavorite(dataType);
	}
}
