package v8_bytecode;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

import org.jdom.JDOMException;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.exec.SleighProgramCompiler;
import ghidra.program.model.lang.ConstantPool;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.lang.PcodeInjectLibrary;
import ghidra.program.model.lang.PcodeParser;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.XmlEncode;

public class V8_PcodeInjectLibrary extends PcodeInjectLibrary {
	private Set<String> implementedOps;
	private SleighLanguage language;
	protected XmlEncode encoder;

	public V8_PcodeInjectLibrary(SleighLanguage l) {
		super(l);
		language = l;
		encoder = new XmlEncode();
		try {
			language.encodeTranslator(encoder, language.getAddressFactory(), getUniqueBase());
		} catch (Exception e) {
			e.printStackTrace();
		}
		String translateSpec = encoder.toString();
		PcodeParser parser = null;
		parser = SleighProgramCompiler.createParser(language);
		implementedOps = new HashSet<>();
		implementedOps.add("InvokeIntrinsicCallOther");
		implementedOps.add("CallRuntimeCallOther");
		implementedOps.add("CallVariadicCallOther");
		implementedOps.add("JSCallNCallOther");
		implementedOps.add("ConstructCallOther");
		implementedOps.add("CallJSRuntimeCallOther");
		implementedOps.add("ThrowCallOther");
		implementedOps.add("StaDataPropertyInLiteralCallOther");
	}

	@Override
	public ConstantPool getConstantPool(Program program) throws IOException {
		return new V8_ConstantPool(program);
	}

	@Override
	/**
	 * This method is called by DecompileCallback.getPcodeInject.
	 */
	public InjectPayload getPayload(int type, String name) {
		if (type == InjectPayload.CALLMECHANISM_TYPE) {
			return null;
		}

		if (!implementedOps.contains(name)) {
			return super.getPayload(type, name);
		}

		V8_InjectPayload payload = null;
		switch (name) {
			case ("InvokeIntrinsicCallOther"):
			case ("CallVariadicCallOther"):
			case ("CallRuntimeCallOther"):
				payload = new V8_InjectCallVariadic("", language, 0);
				break;
			case ("ConstructCallOther"):
				payload = new V8_InjectConstruct("", language, 0);
				break;
			case ("JSCallNCallOther"):
				payload = new V8_InjectJSCallN("", language, 0);
				break;
			case ("CallJSRuntimeCallOther"):
				payload = new V8_InjectCallJSRuntime("", language, 0);
				break;
			case ("ThrowCallOther"):
				payload = new V8_InjectThrow("", language, 0);
				break;
			case ("StaDataPropertyInLiteralCallOther"):
				payload = new V8_InjectStaDataPropertyInLiteral("", language, 0);
				break;
			default:
				return super.getPayload(type, name);
		}

		return payload;
	}

}
