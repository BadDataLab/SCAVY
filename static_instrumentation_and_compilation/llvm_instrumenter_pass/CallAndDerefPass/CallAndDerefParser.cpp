#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/AbstractCallSite.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/IRBuilder.h"

// iterator and user for use-def analysis
#include "llvm/IR/User.h"
#include "llvm/IR/Value.h"
#include "llvm/ADT/iterator.h"
#include "llvm/ADT/iterator_range.h"

// automatically registering pass for Xclang
#include "llvm/PassRegistry.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/IR/LegacyPassManager.h"

// cloning
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/DebugLoc.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/Transforms/Utils/Cloning.h"

// string comparison
#include <string>

using namespace llvm;

// errs() << "\tCalls: [" << directory << "/" << fileName <<
#define PRINT_CALL_SITE(CALL_INST,RETTYPE,RETSTRING) { std::string type_str; \
					llvm::raw_string_ostream rso(type_str); \
					RETTYPE->print(rso); \
					const llvm::DebugLoc &debugInfo = CALL_INST->getDebugLoc(); \
					std::string directory = debugInfo->getDirectory().str(); \
					std::string fileName = debugInfo->getFilename().str(); \
					int line = debugInfo->getLine(); \
					int column = debugInfo->getColumn(); \
					std::string linestr = std::to_string(line); \
					std::string columnstr = std::to_string(column); \
					errs() << "\tCalls: [" << fileName << ":" << line << \
					":" << column << "]`" << CALL_INST->getCalledFunction()->getName() \
					<< "`(" << RETSTRING << ": `" << rso.str() << "`)\n"; }
#define PRINT_CALL_SITE_RETURN(CALL_INST,RETTYPE,RETSTRING) { std::string type_str; \
					llvm::raw_string_ostream rso(type_str); \
					RETTYPE->print(rso); \
					const llvm::DebugLoc &debugInfo = CALL_INST->getDebugLoc(); \
					std::string directory = debugInfo->getDirectory().str(); \
					std::string fileName = debugInfo->getFilename().str(); \
					int line = debugInfo->getLine(); \
					int column = debugInfo->getColumn(); \
					std::string linestr = std::to_string(line); \
					std::string columnstr = std::to_string(column); \
					errs() << "\tCalls-Return-Affected: [" << fileName << ":" << line << \
					":" << column << "]`" << CALL_INST->getCalledFunction()->getName() \
					<< "`(" << RETSTRING << ": `" << rso.str() << "`)\n"; }
#define TOSTRING(VAR,STR) std::string string##STR; \
		llvm::raw_string_ostream STR(string##STR); \
		VAR->print(STR);


/**************************************************** Pass to get all call sites *****************************************************/
namespace {
	struct CallSiteDerefPass : public FunctionPass {
		static char ID;
		CallSiteDerefPass() : FunctionPass(ID) {}

		void recursive_usedef(Instruction* i) {
			// recursive loop through all the operands
			for (llvm::User::op_iterator I = i->op_begin(), E = i->op_end(); I != E; ++I){
				if (Instruction* inst = dyn_cast<Instruction>(I)){
					// don't go recursive on bitcast or call instructions
					if (dyn_cast<BitCastInst>(inst)) {continue;}
					if (dyn_cast<CallInst>(inst)) {continue;}
					recursive_usedef(inst);
				}
			}
			// for bitcast/call instructions do ...
			if (BitCastInst *BCAST = dyn_cast<BitCastInst>(i)) {
				// if the thing that is getting typecasted is coming from a call function
				if (CallInst *call_inst = dyn_cast<CallInst>(BCAST->getOperand(0))) {
					Function* called_function = call_inst->getCalledFunction();
					if (called_function) {
						if (called_function->isIntrinsic()) return;
						PRINT_CALL_SITE_RETURN(call_inst,BCAST->getDestTy(),"typecasted return")
					}
				}
			}
			else if (auto fcall = dyn_cast<CallInst>(i)) {
				Function* called_function = fcall->getCalledFunction();
				if (called_function) {
					if (called_function->isIntrinsic()) return;
					PRINT_CALL_SITE_RETURN(fcall,called_function->getReturnType(),"typecasted return")
				}
			}
		}

		///////////// TODO: Work on this to track the return values of function calls !!! 
		// void recursive_function_ret_tracing(iterator_range<Value::user_iterator> users, CallInst* i) {
		// 		for(auto U : users) {
		// 			if(auto* bcastinst = dyn_cast<BitCastInst>(U)) {
		// 				add_function_call_site(bcastinst,f);
		// 			}
		// 			else if (auto gep = dyn_cast<GetElementPtrInst>(U)) {
		// 				// errs() << "GEP instruction found\n";
		// 				recursive_function_ret_tracing(gep->users(),i);
		// 			}
		// 			else() {
		// 				recursive_function_ret_tracing(U->users(),i);
		// 			}
		// 		}
		// 	}

		bool runOnFunction(Function &F) override {
			if (F.isIntrinsic())
				return false;
			if (F.isDeclaration()) return false;

			// Function in the module and its return type
			errs() << "Function: ";
			errs().write_escaped(F.getName());
			Module *M = F.getParent();
			errs() << "[" << M->getSourceFileName() << "]";
			TOSTRING(F.getReturnType(),rso)
			errs() << " returns:`" << rso.str() << "`\n";

			for (inst_iterator I = inst_begin(F), E = inst_end(F); I != E; ++I) {
				Instruction& inst = *I;
				if (ReturnInst *ri = dyn_cast<ReturnInst>(&inst)) {
					// backwards use-def to see how return value is affected.
					recursive_usedef(&inst);

					if (ri->getNumOperands() == 0) {} // for later use maybe
					else {
						if (ri->getOperand(0)->getType() != F.getReturnType()) {
							TOSTRING(ri->getOperand(0)->getType(),realreturn)
							errs() << "\tBADRETURN-" << realreturn.str() << "\n";
						}
						if (auto *CB = dyn_cast<CallInst>(ri->getOperand(0))) {
							Function* called_function = CB->getCalledFunction();
							if (called_function) {
								if (called_function->isIntrinsic()) continue;
								TOSTRING(CB->getCalledFunction()->getReturnType(),rettype)
								errs() << "\tRETURNSFROMCALL-" << CB->getCalledFunction()->getName() << "\n";
							}
						}
						if (auto *BCAST = dyn_cast<BitCastInst>(ri->getOperand(0))) {
							if (auto *call_inst = dyn_cast<CallInst>(BCAST->getOperand(0))) {
								Function* called_function = call_inst->getCalledFunction();
								if (called_function) {
									if (called_function->isIntrinsic()) continue;
									TOSTRING(BCAST->getDestTy(),rettype)
									errs() << "\tRETURNSFROMCALLTYPECAST-" << rettype.str() << "(" << called_function->getName() << ")" << "\n";
								}
							}
						}
					}
				}
				if (auto *CB = dyn_cast<CallInst>(&inst)) {
					Function* called_function = CB->getCalledFunction();
					if (called_function) {
						if (called_function->isIntrinsic()) continue;
						PRINT_CALL_SITE(CB,called_function->getReturnType(),"return")
					}
				}
				else if (auto *BCAST = dyn_cast<BitCastInst>(&inst)) {
					// if the thing that is getting typecasted is coming from a call function
					if (auto *call_inst = dyn_cast<CallInst>(BCAST->getOperand(0))) {
						Function* called_function = call_inst->getCalledFunction();
						if (called_function) {
							if (called_function->isIntrinsic()) continue;
							PRINT_CALL_SITE(call_inst,BCAST->getDestTy(),"typecasted return")
						}
					}
				}
			}
			return false;
		}
	};
}

char CallSiteDerefPass::ID = 0;
static RegisterPass<CallSiteDerefPass>
X("cdref", "A pass that shows all the function calls and dereferences for every function");

/**************************************************** Pass to get all load instructions *****************************************************/
namespace {
	struct LoadInstTypePass : public FunctionPass {
		static char ID;
		LoadInstTypePass() : FunctionPass(ID) {}

		bool runOnFunction(Function &F) override {
			if (F.isIntrinsic())
				return false;
			if (F.isDeclaration()) return false;

			// Function in the module and its return type
			errs() << "Function: ";
			errs().write_escaped(F.getName());
			Module *M = F.getParent();
			errs() << "[" << M->getSourceFileName() << "]";
			TOSTRING(F.getReturnType(),rso)
			errs() << " returns:`" << rso.str() << "`\n";

			for (inst_iterator I = inst_begin(F), E = inst_end(F); I != E; ++I) {
				Instruction& inst = *I;
				if (auto *CB = dyn_cast<LoadInst>(&inst)) {
					TOSTRING(CB->getType(),loadtype)
					errs() << "Loaded memory of type: " << loadtype.str() << "\n";
				}
			}
			return false;
		}
	};
}

char LoadInstTypePass::ID = 0;
static RegisterPass<LoadInstTypePass>
AAA("loadtype", "A pass that shows the type of the value of the load instruction.");


/****************************************** Pass to insert a function call in bitcast instructions ****************************************/
namespace {
  	struct ModifyTypecasts : public FunctionPass {
		static char ID;
		ModifyTypecasts() : FunctionPass(ID) {}

		bool add_function_call_site(BitCastInst* i, Function* F) {
			// only add function call if typecast is typecasting from pointer into pointer and the destination pointer is struct
			if (!(i->getDestTy()->isPtrOrPtrVectorTy()
			&& i->getSrcTy()->isPtrOrPtrVectorTy() && !(i->getSrcTy()->getPointerElementType()->isStructTy())
			&& i->getDestTy()->getPointerElementType()->isStructTy())) {
				return false;
			}

			// only focus on a specific struct type. -->  `file`
			auto structName = i->getDestTy()->getPointerElementType()->getStructName();
			// if (!(structName.equals("struct.cred") 
			// || structName.equals("struct.vm_area_struct")
			// || structName.equals("struct.fname")
			// || structName.equals("struct.dentry")
			// || structName.equals("struct.filename"))) { // i->getDestTy()->getPointerElementType()->getStructName().find("file") != std::string::npos) {
			// 	return false;
			// }

			Module *M = F->getParent();

			LLVMContext &context = M->getContext();
			FunctionType *functionType = FunctionType::get(Type::getVoidTy(context),
					{Type::getInt8PtrTy(context),Type::getInt8PtrTy(context),
					Type::getInt8PtrTy(context),Type::getInt8PtrTy(context)}, false);


			FunctionCallee inserted_f = M->getOrInsertFunction("print_typecast_instruction", functionType);
			

			// Function* inserted_f =  M->getFunction("print_typecast_instruction");
			// if (inserted_f == nullptr) {
			// 	return 0;
			// }

			// 	inserted_f =  M->getFunction("print_typecast_instruction_" + M->getName().str());
			// 	// errs() << "\tDid not modify the callsite because function not found!\n";
			// 	if(inserted_f == nullptr) return 0;
			// } else {
			// 	ValueToValueMapTy VMap;
			// 	Function* cloned_function = llvm::CloneFunction(inserted_f,VMap,nullptr);

			// 	StringRef newname = "print_typecast_instruction_" + M->getName().str();// + "_" + F->getName().str();
			// 	cloned_function->setName(newname);
			// 	inserted_f->eraseFromParent();
			// 	inserted_f = cloned_function;
			// 	errs() << "Cloned function into " << newname.str() << "\n";
			// }

			IRBuilder<> builder(i);
			Value *typecasted_variable = dyn_cast<Value>(i->getOperand(0));
			
			if (typecasted_variable == nullptr) {
				errs() << "[ERROR] Some issue with operand of BitCast! \n";
				return 0;
			}
			
			TOSTRING(i->getDestTy(),deststr)
			TOSTRING(i->getSrcTy(),srcstr)
			Value *destination_val = builder.CreateGlobalStringPtr(deststr.str(), ".str");
			Value *source_val = builder.CreateGlobalStringPtr(srcstr.str(), ".str");
			const llvm::DebugLoc &debugInfo = i->getDebugLoc();
			
			

			if (debugInfo) {
				// Twine directory = Twine(debugInfo->getDirectory());
				Twine fileName = Twine(debugInfo->getFilename());
				int line = debugInfo->getLine();
				int column = debugInfo->getColumn();
				Twine linestr = Twine(std::to_string(line));
				Twine columnstr = Twine(std::to_string(column));
				// Twine location = directory+
				Twine location = fileName+":"+linestr+columnstr+"{"+F->getName()+"}";
				Value *function_name = builder.CreateGlobalStringPtr(location.str(), ".str");
				builder.CreateCall(inserted_f,{function_name,typecasted_variable,source_val,destination_val});
				errs() << "[SUCCESS] Typecaster instruction instrumented (from:" << srcstr.str() << ")(to: " << deststr.str() << ")\n";
			} else {
				errs() << "[WARNING] Debug values are disabled (function line number will not get printed)!\n";
				Value *function_name = builder.CreateGlobalStringPtr(F->getName().str(), ".str");
				builder.CreateCall(inserted_f,{function_name,typecasted_variable,source_val,destination_val});
			}
			return 1;
		}

		int recursive_user_iterator(iterator_range<Value::user_iterator> users, Function* f) {
			for(auto U : users) {
				if(auto* bcastinst = dyn_cast<BitCastInst>(U)) {
					add_function_call_site(bcastinst,f);
					return 1;
				}
				//else if (auto gep = dyn_cast<GetElementPtrInst>(U)) {
				//	return 0 + recursive_user_iterator(gep->users(),f);
				//}
				else {
					return 0 + recursive_user_iterator(U->users(),f);
				}
				// else if (auto fcall = dyn_cast<CallInst>(U)) {
				// 	errs() << "Need to monitor parameter types of " << fcall->getFunction()->getName() << "\n";
				// }
			}
			return 0;
		}

		bool runOnFunction(Function &F) override {
			if (F.isIntrinsic())
				return false;
			if (F.isDeclaration()) return false;

			int number_of_calls_added = 0;
			for (inst_iterator I = inst_begin(F), E = inst_end(F); I != E; ++I) {
				Instruction& inst = *I;
				//////////////// INSTRUMENT BITCAST INSTRUCTIONS AFTER A CALL SITE //////////////
				if (auto * fcall = dyn_cast<CallInst>(&inst)) {
				 	// if function has a return value
				 	Function* f = fcall->getFunction();
				 	if ( !f->getReturnType()->isVoidTy() ) {
				 		number_of_calls_added += recursive_user_iterator(fcall->users(),&F);
				 	}
				}
				/////////////////////////////////////////////////////////////////////////////////

				////////////////////// INSTRUMENT ALL BITCAST INSTRUCTIONS //////////////////////
				//if (auto * bcast = dyn_cast<BitCastInst>(&inst)) {
				//	add_function_call_site(bcast, &F);
				//}
				/////////////////////////////////////////////////////////////////////////////////
			}
			return (number_of_calls_added > 0);
		}
  	};
}

char ModifyTypecasts::ID = 0;
static RegisterPass<ModifyTypecasts>
Y("modtcasts", "A pass that modifies all typecast instructions such that their operands are used in another function.");

static void registerMyPass(const PassManagerBuilder &,
                           legacy::PassManagerBase &PM) {
    PM.add(new ModifyTypecasts());
}
static RegisterStandardPasses
    RegisterMyPass(PassManagerBuilder::EP_EarlyAsPossible,
                   registerMyPass);


/**************************************************** Pass to debug modules *****************************************************/
namespace {
	struct ModFunctions : public ModulePass  {
		static char ID;
		ModFunctions() : ModulePass(ID) {}
		bool runOnModule(Module &M) override {
			for (auto curFref = M.getFunctionList().begin(), 
				endFref = M.getFunctionList().end(); 
				curFref != endFref; ++curFref) {
				errs() << "In module: " << M.getSourceFileName();
				errs() << " found function: " << curFref->getName() << "\n";
				Function * F = dyn_cast<Function>(curFref);
				int i = 0;
				for(auto arg = F->arg_begin(); arg != F->arg_end(); ++arg) {
					TOSTRING(arg->getType(),ptype)
					if(auto* ci = dyn_cast<ConstantInt>(arg))
						errs() << "\tParameter-" << i << "-: `" << ci->getValue() << "`" << ptype.str() << "\n";
					else {
						errs() << "\tParameter-" << i << "-: `" << arg->getName() << "`" << ptype.str() << "\n";
					}
					i++;
				}
			}
			errs() << "\n";
			errs() << "Module ifuncts: ";
			
			for (Module::ifunc_iterator I = M.ifunc_begin(), E = M.ifunc_end(); I != E; ++I) {
				Value * v = dyn_cast<Value>(I);
				errs() << v->getName() << " ";
			}
			errs() << "\n\n";
			return false;
		}

		// We don't modify the program, so we preserve all analyses.
		void getAnalysisUsage(AnalysisUsage &AU) const override {
			AU.setPreservesAll();
		}
	};
}

char ModFunctions::ID = 0;
static RegisterPass<ModFunctions>
Z("modfunctions", "A pass that shows all the function in the module");


namespace {
	struct StructsInFunctionPass : public FunctionPass {
		static char ID;
		StructsInFunctionPass() : FunctionPass(ID) {}

		bool runOnFunction(Function &F) override {
			if (F.isIntrinsic()) return false;
			if (F.isDeclaration()) return false;

			// Function in the module and its return type
			errs() << "Function: ";
			errs().write_escaped(F.getName());
			Module *M = F.getParent();
			errs() << "[" << M->getSourceFileName() << "]";
			TOSTRING(F.getReturnType(),rso)
			errs() << " returns:`" << rso.str() << "`\n";


			for(auto arg = F.arg_begin(); arg != F.arg_end(); ++arg) {
				TOSTRING(arg->getType(),argtype)
				errs() << "\tUses:`" << argtype.str() << "`\n";
			}


			for (inst_iterator I = inst_begin(F), E = inst_end(F); I != E; ++I) {
				Instruction& inst = *I;
				for (unsigned int opnum = 0; opnum < inst.getNumOperands(); opnum++) {
					TOSTRING(inst.getOperand(opnum)->getType(),optype)
					errs() << "\tUses:`" << optype.str() << "`\n";
				}
			}
			return false;
		}
	};
}

char StructsInFunctionPass::ID = 0;
static RegisterPass<StructsInFunctionPass>
W("funcstructs", "A pass that shows all the structure types used in all the instructions of a function.");

/*
************************ A working module pass template ************************
namespace {
	// Hello3 - The second implementation with getAnalysisUsage implemented.
	struct Hello3 : public ModulePass  {
		static char ID; // Pass identification, replacement for typeid
		Hello3() : ModulePass(ID) {}
		bool runOnModule(Module &M) override {
			for (auto curFref = M.getFunctionList().begin(), 
				endFref = M.getFunctionList().end(); 
				curFref != endFref; ++curFref) {
				errs() << "found function: " << curFref->getName() << "\n";
			}
		}

		// We don't modify the program, so we preserve all analyses.
		void getAnalysisUsage(AnalysisUsage &AU) const override {
			AU.setPreservesAll();
		}
	};
}

char Hello3::ID = 0;
static RegisterPass<Hello3>
Z("hello3", "Hello World Pass 3");
*/
